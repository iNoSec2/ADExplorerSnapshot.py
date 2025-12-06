"""
Create synthetic AD objects for missing intermediate containers.

When building treeview, some DNs may reference parent containers that don't
exist as actual objects in the snapshot. This module creates minimal synthetic
objects for these missing parents.
"""

import struct


def create_synthetic_object(dn, snap):
    """
    Create a minimal synthetic AD object for a missing container DN.
    
    Returns bytes of the object structure.
    
    Structure:
    - objSize (uint32)
    - tableSize (uint32) 
    - mappingTable entries (8 bytes each)
    - attribute data
    """
    from io import BytesIO
    
    # Find property index for distinguishedName
    dn_prop_idx = snap.propertyDict.get('distinguishedName')
    
    if dn_prop_idx is None:
        raise ValueError("Cannot create synthetic object: missing distinguishedName property")
    
    # Only one attribute: distinguishedName
    table_size = 1
    
    # Attribute data starts after: objSize(4) + tableSize(4) + mappingTable(1 * 8) = 16
    attr_data_start = 8 + (table_size * 8)
    
    # Build attribute data
    attr_buf = BytesIO()
    
    # Attribute: distinguishedName
    # Format: [numValues][offset_array][string_data]
    dn_attr_offset = attr_data_start
    dn_encoded = dn.encode('utf-16le') + b'\x00\x00'
    attr_buf.write(struct.pack("<I", 1))  # num values
    attr_buf.write(struct.pack("<I", 8))  # offset within attribute (after numValues + offset = 8)
    attr_buf.write(dn_encoded)
    
    # Build mapping table
    mapping_table = [
        (dn_prop_idx, dn_attr_offset)
    ]
    
    # Calculate total size
    attr_data = attr_buf.getvalue()
    obj_size = 8 + (table_size * 8) + len(attr_data)
    
    # Build complete object
    obj_buf = BytesIO()
    obj_buf.write(struct.pack("<I", obj_size))
    obj_buf.write(struct.pack("<I", table_size))
    
    for attr_idx, attr_offset in mapping_table:
        obj_buf.write(struct.pack("<I", attr_idx))  # attrIndex (unsigned)
        obj_buf.write(struct.pack("<i", attr_offset))  # attrOffset (signed, can be negative)
    
    obj_buf.write(attr_data)
    
    return obj_buf.getvalue()


def create_synthetic_objects_data(missing_dns, snap, start_offset):
    """
    Create synthetic AD objects for missing intermediate containers.
    
    Args:
        missing_dns: Set of DN strings for missing parents
        snap: Snapshot object (for property indices)
        start_offset: File offset where synthetic objects will be written
    
    Returns:
        (synthetic_objects_dict, synthetic_data_bytes)
        synthetic_objects_dict: DN -> {'obj_idx', 'obj_offset'}
        synthetic_data_bytes: concatenated binary data for all synthetic objects
    """
    if not missing_dns:
        return {}, b''
    
    from io import BytesIO
    
    synthetic_objects = {}
    all_data = BytesIO()
    current_offset = start_offset
    current_idx = len(snap.objectOffsets)  # Start after real objects
    
    # Sort by DN length to create parents before children
    for dn in sorted(missing_dns, key=len):
        obj_data = create_synthetic_object(dn, snap)
        
        synthetic_objects[dn] = {
            'obj_idx': current_idx,
            'obj_offset': current_offset
        }
        
        all_data.write(obj_data)
        current_offset += len(obj_data)
        current_idx += 1
    
    return synthetic_objects, all_data.getvalue()

