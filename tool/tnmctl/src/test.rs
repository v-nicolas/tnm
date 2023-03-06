use crate::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_set_ip_version() {
        assert_eq!(ctl::set_ip_version(1, "toto"), 0);
    }
}
