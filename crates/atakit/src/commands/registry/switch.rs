use anyhow::Result;
use clap::Args;

use crate::Env;

/// Switch to a different registry branch.
#[derive(Args)]
pub struct Switch {
    /// Branch name to switch to
    pub branch: String,
}

impl Switch {
    pub fn run(self, env: &Env) -> Result<()> {
        let store = env.registry_store();
        let old_branch = store.current_branch()?;

        store.switch_branch(&self.branch)?;

        if old_branch == self.branch {
            println!("Already on branch '{}'", self.branch);
        } else {
            println!("Switched from '{}' to '{}'", old_branch, self.branch);
        }

        Ok(())
    }
}
