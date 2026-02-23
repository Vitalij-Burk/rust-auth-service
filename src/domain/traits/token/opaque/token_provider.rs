pub trait IOpaqueTokenProvider {
    fn generate(&self) -> String;
}
