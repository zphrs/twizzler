use twizzler_abi::pager::{CompletionToKernel, KernelCompletionData, RequestFromKernel};

async fn handle_request(_request: RequestFromKernel) -> Option<CompletionToKernel> {
    Some(CompletionToKernel::new(KernelCompletionData::EchoResp))
}

fn main() {
    println!("Hello, world");
}
