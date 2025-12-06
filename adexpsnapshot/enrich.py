"""
Treeview metadata enrichment functionality.

Detects if treeview metadata is missing and reconstructs it if needed.
"""

import struct
from pathlib import Path
from collections import defaultdict


TREEVIEW_MAGIC = b'\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF'  # First 8 bytes of treeview header


def check_treeview_exists(snap):
    """
    Check if treeview metadata exists at the offset specified in header.
    
    Returns (exists: bool, treeview_offset: int)
    """
    try:
        treeview_offset = snap.header.treeviewOffset
        
        if treeview_offset == 0 or treeview_offset == 0xFFFFFFFFFFFFFFFF:
            return False, 0
        
        # Check if file is large enough to contain treeview
        snap.fh.seek(0, 2)  # Seek to end
        file_size = snap.fh.tell()
        
        # Need at least header (64 bytes) + some section data
        min_required = treeview_offset + 64 + 100  # Header + minimal sections
        
        if file_size < min_required:
            return False, treeview_offset
        
        snap.fh.seek(treeview_offset)
        magic = snap.fh.read(8)
        
        if magic != TREEVIEW_MAGIC:
            return False, treeview_offset
        
        # Check if there's actually complete data
        header_data = snap.fh.read(56)  # Remaining header bytes
        if len(header_data) < 56:
            return False, treeview_offset
        
        header_words = struct.unpack("<14I", header_data)
        
        # Sanity check: num_NCs should be 3 (or reasonable)
        num_ncs = header_words[0]  # This is header[2]
        if num_ncs < 1 or num_ncs > 10:
            return False, treeview_offset
        
        # Verify sections exist and have reasonable sizes
        section1_offset = header_words[2]  # header[4]
        section2_offset = header_words[3]  # header[5]
        section3_offset = header_words[4]  # header[6]
        
        # Check if file contains all three sections
        expected_min_size = treeview_offset + 64 + section3_offset + 100
        
        if file_size < expected_min_size:
            return False, treeview_offset
        
        return True, treeview_offset
    except:
        return False, 0


def get_output_filename(input_path):
    """
    Generate output filename: input.enriched.ext
    
    Examples:
    - snapshot.dat -> snapshot.enriched.dat
    - snapshot -> snapshot.enriched
    - file.xyz -> file.enriched.xyz
    """
    path = Path(input_path.name)
    
    if path.suffix:
        # Has extension: insert .enriched before it
        stem = path.stem
        suffix = path.suffix
        new_name = f"{stem}.enriched{suffix}"
    else:
        # No extension: just append .enriched
        new_name = f"{path.name}.enriched"
    
    return path.parent / new_name


# Removed - now imported from section_encoder_clean


def enrich_snapshot(ades):
    """
    Main enrichment function.
    
    Checks if treeview metadata exists, reconstructs if missing, saves to new file.
    
    Args:
        ades: ADExplorerSnapshot instance (already initialized)
    """
    snap = ades.snap
    snapshot_file = ades.snapfile
    console = ades.console
    
    console.print(f"[cyan]Checking snapshot:[/cyan] {snapshot_file.name}")
    
    # Check if treeview exists
    has_treeview, treeview_offset = check_treeview_exists(snap)
    
    console.print(f"[cyan]Treeview offset from header:[/cyan] 0x{treeview_offset:x}")
    
    if has_treeview:
        console.print("[green]Treeview metadata already exists[/green]")
        console.print("No enrichment needed.")
        return
    
    console.print("[yellow]! Treeview metadata missing or invalid[/yellow]")
    console.print("Reconstructing treeview metadata...")
    
    # If treeview_offset is 0 or invalid, use default position (after objects)
    if treeview_offset == 0:
        # Calculate where treeview should go (after last object)
        last_obj_offset = snap.objectOffsets[-1]
        snapshot_file.seek(last_obj_offset)
        last_obj_size = struct.unpack("<I", snapshot_file.read(4))[0]
        treeview_offset = last_obj_offset + last_obj_size
        console.print(f"[cyan]Calculated treeview offset:[/cyan] 0x{treeview_offset:x}")
    
    console.print(f"[cyan]Parsed {len(snap.objectOffsets)} objects[/cyan]")
    
    # Use existing preprocessing with cache
    console.print("[cyan]Loading DN cache...[/cyan]")
    ades.preprocessCached()
    dncache = ades.dncache
    
    # Import tree building and encoding functions
    from adexpsnapshot.section_encoder_clean import build_nc_tree, encode_section
    
    # Identify NC roots from the snapshot
    domain_root = ades.rootdomain
    if not domain_root:
        console.print("[red]✗ No domain root found in snapshot![/red]")
        return
    
    # Configuration NC is always CN=Configuration,<domain_root>
    # Schema NC is always CN=Schema,CN=Configuration,<domain_root>
    config_root = f"CN=Configuration,{domain_root}"
    schema_root = f"CN=Schema,CN=Configuration,{domain_root}"
    domain_dns_zones_root = f"DC=DomainDnsZones,{domain_root}"
    forest_dns_zones_root = f"DC=ForestDnsZones,{domain_root}"
    
    console.print(f"[cyan]Naming contexts:[/cyan]")
    console.print(f"  Domain: {domain_root}")
    console.print(f"  Config: {config_root}")
    console.print(f"  Schema: {schema_root}")
    console.print(f"  Domain DNS Zones: {domain_dns_zones_root}")
    console.print(f"  Forest DNS Zones: {forest_dns_zones_root}")
    
    # Check which optional NCs exist
    has_domain_dns = any(dn.endswith(domain_dns_zones_root) for dn in dncache.keys())
    has_forest_dns = any(dn.endswith(forest_dns_zones_root) for dn in dncache.keys())
    
    # Determine number of NCs upfront
    num_ncs = 3 + (1 if has_domain_dns else 0) + (1 if has_forest_dns else 0)
    console.print(f"[cyan]Total naming contexts: {num_ncs}[/cyan]")
    
    # Build trees and collect missing parents on-demand
    console.print("[cyan]Building trees and identifying missing containers...[/cyan]")
    synthetic_collector = {}  # Will be populated during tree building
    
    console.print("[cyan]Building Domain NC tree...[/cyan]")
    domain_tree = build_nc_tree(snap, domain_root, lambda dn: dn.endswith(domain_root) and not dn.endswith(config_root) and not dn.endswith(domain_dns_zones_root) and not dn.endswith(forest_dns_zones_root), dncache, synthetic_collector)
    
    console.print("[cyan]Building Configuration NC tree...[/cyan]")
    config_tree = build_nc_tree(snap, config_root, lambda dn: dn.endswith(config_root) and not dn.endswith(schema_root), dncache, synthetic_collector)
    
    console.print("[cyan]Building Schema NC tree...[/cyan]")
    schema_tree = build_nc_tree(snap, schema_root, lambda dn: dn.endswith(schema_root), dncache, synthetic_collector)

    domain_dns_zones_tree = None
    if has_domain_dns:
        console.print(f"[cyan]Building Domain DNS Zones NC tree...[/cyan]")
        domain_dns_zones_tree = build_nc_tree(snap, domain_dns_zones_root, lambda dn: dn.endswith(domain_dns_zones_root), dncache, synthetic_collector)

    forest_dns_zones_tree = None
    if has_forest_dns:
        console.print(f"[cyan]Building Forest DNS Zones NC tree...[/cyan]")
        forest_dns_zones_tree = build_nc_tree(snap, forest_dns_zones_root, lambda dn: dn.endswith(forest_dns_zones_root), dncache, synthetic_collector)
    
    # Create synthetic objects for all missing parents found during tree building
    synthetic_data = b''
    if synthetic_collector:
        console.print(f"[yellow]Creating {len(synthetic_collector)} synthetic containers...[/yellow]")
        from adexpsnapshot.treeview.synthetic import create_synthetic_objects_data
        
        # Synthetics go at treeview_offset
        synthetic_objects, synthetic_data = create_synthetic_objects_data(
            set(synthetic_collector.keys()), snap, treeview_offset
        )
        
        console.print(f"[cyan]Synthetic objects data: {len(synthetic_data)} bytes[/cyan]")
        for dn, info in list(synthetic_objects.items())[:3]:
            console.print(f"  {dn}")
            console.print(f"    obj_idx={info['obj_idx']}, obj_offset=0x{info['obj_offset']:x}")
        
        # Update all trees with actual synthetic object info
        def update_synthetics(node):
            """Recursively update synthetic nodes with real obj_idx/obj_offset."""
            dn = node['dn']
            # Check if this is a synthetic node (negative temp index)
            if node['obj_idx'] < 0:
                if dn in synthetic_objects:
                    old_idx = node['obj_idx']
                    node['obj_idx'] = synthetic_objects[dn]['obj_idx']
                    node['obj_offset'] = synthetic_objects[dn]['obj_offset']
                    console.print(f"[dim]Updated {dn}: idx {old_idx} → {node['obj_idx']}, offset 0x{node['obj_offset']:x}[/dim]")
            for child in node.get('children', []):
                update_synthetics(child)
        
        console.print("[cyan]Updating tree nodes with synthetic object info...[/cyan]")
        update_synthetics(domain_tree)
        update_synthetics(config_tree)
        update_synthetics(schema_tree)
        if domain_dns_zones_tree:
            update_synthetics(domain_dns_zones_tree)
        if forest_dns_zones_tree:
            update_synthetics(forest_dns_zones_tree)
    
    # Require core 3 NCs (Domain, Config, Schema)
    if not all([domain_tree, config_tree, schema_tree]):
        console.print("[red]✗ Failed to build required NC trees (Domain/Config/Schema)[/red]")
        return
    
    # Encode all sections with clean universal algorithm
    sections = []
    section_names = [
        ("Domain NC", domain_tree),
        ("Configuration NC", config_tree),
        ("Schema NC", schema_tree)
    ]
    
    # Add optional DNS zones if present
    if domain_dns_zones_tree:
        section_names.append(("Domain DNS Zones NC", domain_dns_zones_tree))
    if forest_dns_zones_tree:
        section_names.append(("Forest DNS Zones NC", forest_dns_zones_tree))
    
    for name, tree in section_names:
        console.print(f"[cyan]Encoding {name}...[/cyan]")
        section_data = bytes(encode_section(tree, snap))
        sections.append(section_data)

    num_ncs = len(section_names)
    
    console.print(f"[green]Encoded {num_ncs} NC sections: {', '.join(str(len(s)) for s in sections)} bytes[/green]")
    
    # Build treeview header using cstruct with variable-length array
    from adexpsnapshot.treeview.structure import treeview_structure
    
    # Calculate header size
    header_size = 16 + (num_ncs * 4)
    
    # Calculate section offsets (relative to treeview start, after header)
    # Layout: [Treeview Header][Section1][Section2][...]
    section_offsets = []
    current_offset = header_size
    for section in sections:
        section_offsets.append(current_offset)
        current_offset += len(section)
    
    header_struct = treeview_structure.TreeviewHeader()
    header_struct.magic = 0xFFFFFFFFFFFFFFFE  # Combined 64-bit magic
    header_struct.num_NCs = num_ncs  # Dynamic: 3-5 depending on DNS zones presence
    header_struct.reserved = 0
    header_struct.section_offsets = section_offsets
    
    header = header_struct.dumps()
    
    # Read original file
    snapshot_file.seek(0)
    original_data = bytearray(snapshot_file.read())
    
    # Fix header signature if needed (ensure first 3 bytes are 'win')
    if original_data[:3] != b'win':
        console.print(f"[yellow]! Fixing header signature: {original_data[:3]} -> b'win'[/yellow]")
        original_data[0:3] = b'win'
    
    # Create enriched file
    output_path = get_output_filename(Path(snapshot_file.name))
    
    console.print(f"[cyan]Writing enriched snapshot to:[/cyan] {output_path}")
    
    # Update treeviewOffset in main file header if we have synthetic objects
    # New treeview starts after synthetic objects
    new_treeview_offset = treeview_offset + len(synthetic_data)
    
    if synthetic_data:
        # Update treeviewOffset field in main file header (at offset 0x424)
        struct.pack_into("<Q", original_data, 0x436, new_treeview_offset)
        console.print(f"[yellow]Updated treeviewOffset: 0x{treeview_offset:x} → 0x{new_treeview_offset:x}[/yellow]")
    
    # Calculate sizes
    treeview_metadata_size = len(header) + sum(len(s) for s in sections)
    total_added = len(synthetic_data) + treeview_metadata_size
    
    with open(output_path, 'wb') as out:
        # Write original data up to original treeview offset
        out.write(original_data[:treeview_offset])
        
        # Write synthetic objects (if any) BEFORE treeview
        if synthetic_data:
            out.write(synthetic_data)
        
        # Write treeview metadata: [Header][Sections...]
        out.write(header)
        for section in sections:
            out.write(section)
        
        # If original had data after treeview, preserve it
        # (though typically treeview is at EOF)
        if len(original_data) > treeview_offset:
            remaining_start = treeview_offset + total_added
            if len(original_data) > remaining_start:
                out.write(original_data[remaining_start:])
    
    console.print(f"[green]Enriched snapshot saved![/green]")
    console.print(f"Original size: {len(original_data):,} bytes")
    console.print(f"Enriched size: {output_path.stat().st_size:,} bytes")
    if synthetic_data:
        console.print(f"Added synthetic objects: {len(synthetic_data):,} bytes ({len(synthetic_collector)} containers)")
    console.print(f"Added treeview metadata: {treeview_metadata_size:,} bytes")

