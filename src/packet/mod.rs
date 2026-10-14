#![allow(dead_code)]

pub mod convs;
pub mod dissector;
pub mod filter;
pub mod loader;
pub mod stream;
pub mod tshark;

use std::ops::Range;

/// Represents a single field or protocol level node in the packet structure view
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub title: String,
    pub field_name: String,
    pub field_val: String,
    pub byte_range: Option<Range<usize>>,
    pub children: Vec<TreeNode>,
    pub expanded: bool,
}

impl TreeNode {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            field_name: String::new(),
            field_val: String::new(),
            byte_range: None,
            children: Vec::new(),
            expanded: false,
        }
    }

    pub fn with_range(mut self, range: Range<usize>) -> Self {
        self.byte_range = Some(range);
        self
    }

    pub fn with_field(mut self, name: impl Into<String>, val: impl Into<String>) -> Self {
        self.field_name = name.into();
        self.field_val = val.into();
        self
    }

    pub fn with_expanded(mut self, expanded: bool) -> Self {
        self.expanded = expanded;
        self
    }

    pub fn add_child(&mut self, child: TreeNode) {
        self.children.push(child);
    }

    /// Recursively expand or collapse all nodes in this subtree
    pub fn set_expanded_all(&mut self, expanded: bool) {
        self.expanded = expanded;
        for child in &mut self.children {
            child.set_expanded_all(expanded);
        }
    }

    /// Flatten the visible tree based on expansion state into a list of (depth, node_reference)
    pub fn flatten_visible<'a>(&'a self, depth: usize, out: &mut Vec<(usize, &'a TreeNode)>) {
        out.push((depth, self));
        if self.expanded {
            for child in &self.children {
                child.flatten_visible(depth + 1, out);
            }
        }
    }
}

/// Dissection tree for a packet
#[derive(Debug, Clone, Default)]
pub struct DissectionTree {
    pub root_nodes: Vec<TreeNode>,
}

impl DissectionTree {
    pub fn new() -> Self {
        Self {
            root_nodes: Vec::new(),
        }
    }

    pub fn add_root(&mut self, node: TreeNode) {
        self.root_nodes.push(node);
    }

    pub fn set_all_expanded(&mut self, expanded: bool) {
        for node in &mut self.root_nodes {
            node.set_expanded_all(expanded);
        }
    }

    /// Flatten all currently visible nodes in preorder: (path_indices, depth, &TreeNode)
    pub fn visible_nodes(&self) -> Vec<(Vec<usize>, usize, &TreeNode)> {
        let mut result = Vec::new();
        for (i, root) in self.root_nodes.iter().enumerate() {
            Self::flatten_node(&[i], root, 0, &mut result);
        }
        result
    }

    fn flatten_node<'a>(
        path: &[usize],
        node: &'a TreeNode,
        depth: usize,
        out: &mut Vec<(Vec<usize>, usize, &'a TreeNode)>,
    ) {
        out.push((path.to_vec(), depth, node));
        if node.expanded {
            for (child_idx, child) in node.children.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(child_idx);
                Self::flatten_node(&child_path, child, depth + 1, out);
            }
        }
    }

    /// Find node by hierarchical index path
    pub fn get_node_mut(&mut self, path: &[usize]) -> Option<&mut TreeNode> {
        if path.is_empty() {
            return None;
        }
        let mut curr = self.root_nodes.get_mut(path[0])?;
        for &idx in &path[1..] {
            curr = curr.children.get_mut(idx)?;
        }
        Some(curr)
    }

    pub fn get_node(&self, path: &[usize]) -> Option<&TreeNode> {
        if path.is_empty() {
            return None;
        }
        let mut curr = self.root_nodes.get(path[0])?;
        for &idx in &path[1..] {
            curr = curr.children.get(idx)?;
        }
        Some(curr)
    }
}

/// One-line packet summary displayed in the packet table
#[derive(Debug, Clone)]
pub struct PacketSummary {
    pub num: usize,
    pub rel_time_secs: f64,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
}

/// Complete packet representation
#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub summary: PacketSummary,
    pub raw_data: Vec<u8>,
    pub timestamp_secs: u64,
    pub timestamp_nanos: u32,
    pub tree: DissectionTree,
}
