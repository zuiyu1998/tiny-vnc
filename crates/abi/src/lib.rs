mod error;

use error::Result;

pub struct VPNInstance {}

impl VPNInstance {
    pub async fn run() -> Result<()> {
        Ok(())
    }
}
