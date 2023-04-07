use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn pyclass(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn pymethods(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn staticmethod(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn new(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn pyfunction(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn pymodule(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn pyproto(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn getter(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn setter(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn pyo3(_: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_derive(FromPyObject, attributes(pyo3, extract))]
pub fn hello_macro_derive(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}