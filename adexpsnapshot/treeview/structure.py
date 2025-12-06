from dissect.cstruct import cstruct

treeview_structure = cstruct()
treeview_structure.load("""
    // Treeview header - supports variable number of naming contexts
    struct TreeviewHeader {
        uint64 magic;                   // 0xFFFFFFFFFFFFFFFE
        uint32 num_NCs;                 // Number of naming contexts (usually 3: Domain, Configuration, Schema)
        uint32 reserved;                // 0
        uint32 section_offsets[num_NCs]; // Byte offsets to each NC section (relative to start of treeview metadata)
    };
    
    // Parent node - complete structure with variable-length arrays
    // All nodes in the treeview are ParentNodes
    // (Leaf children are stored inline in their parent's inline_child_offsets)
    struct ParentNode {
        uint64 objectOffset;
        uint32 num_children_with_children;    // Number of children that have their own ParentNode entries
        uint32 num_children_without_children; // Number of leaf children (stored inline below)
        uint32 child_offsets[num_children_with_children];           // Relative byte offsets to child ParentNode entries
        uint64 inline_child_offsets[num_children_without_children]; // Direct objectOffsets for leaf children (no standalone entry)
    };
    
""", compiled=True)

