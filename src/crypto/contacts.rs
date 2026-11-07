use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub public_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactBook {
    contacts: HashMap<String, Contact>,
}

impl ContactBook {
    pub fn new() -> Self {
        ContactBook { contacts: HashMap::new() }
    }

    pub fn load(path: &str) -> Self {
        let p = Path::new(path);
        if !p.exists() {
            return ContactBook::new();
        }
        let data = fs::read_to_string(p).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_else(|_| ContactBook::new())
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize contacts: {}", e))?;
        fs::write(path, data).map_err(|e| format!("Failed to save contacts: {}", e))
    }

    pub fn add(&mut self, name: String, public_key_hex: String) {
        self.contacts
            .insert(name.clone(), Contact { name, public_key_hex });
    }

    pub fn get(&self, name: &str) -> Option<&Contact> {
        self.contacts.get(name)
    }

    pub fn list(&self) -> Vec<&Contact> {
        let mut list: Vec<&Contact> = self.contacts.values().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }
}
