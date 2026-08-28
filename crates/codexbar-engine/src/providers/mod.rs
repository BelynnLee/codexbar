mod abacus;
mod amp;
mod augment;
mod azureopenai;
mod chutes;
mod claude;
mod clawrouter;
mod codebuff;
mod codex;
mod commandcode;
mod copilot;
mod crof;
mod crossmodel;
mod cursor;
mod deepgram;
mod deepseek;
mod elevenlabs;
mod groq;
mod kilo;
mod kimi;
mod kimik2;
mod litellm;
mod llmproxy;
mod manus;
mod mimo;
mod minimax;
mod moonshot;
mod openai;
mod opencode;
mod opencode_zen;
mod openrouter;
mod perplexity;
mod poe;
mod qoder;
mod stepfun;
mod sub2api;
mod synthetic;
mod t3chat;
mod venice;
mod wayfinder;
mod zai;

use crate::provider::Provider;
use std::sync::Arc;

pub fn all_providers() -> Vec<Arc<dyn Provider>> {
    vec![
        Arc::new(claude::ClaudeProvider::default()),
        Arc::new(codex::CodexProvider),
        Arc::new(copilot::CopilotProvider),
        Arc::new(cursor::CursorProvider::default()),
        Arc::new(opencode::OpenCodeProvider),
        Arc::new(opencode_zen::OpenCodeZenProvider),
        Arc::new(openrouter::OpenRouterProvider),
        Arc::new(deepseek::DeepSeekProvider),
        Arc::new(moonshot::MoonshotProvider::default()),
        Arc::new(venice::VeniceProvider),
        Arc::new(poe::PoeProvider),
        Arc::new(groq::GroqProvider),
        Arc::new(elevenlabs::ElevenLabsProvider),
        Arc::new(deepgram::DeepgramProvider),
        Arc::new(kimik2::KimiK2Provider),
        Arc::new(crossmodel::CrossModelProvider),
        Arc::new(clawrouter::ClawRouterProvider),
        Arc::new(crof::CrofProvider),
        Arc::new(codebuff::CodebuffProvider),
        Arc::new(llmproxy::LLMProxyProvider),
        Arc::new(openai::OpenAIProvider),
        Arc::new(chutes::ChutesProvider),
        Arc::new(synthetic::SyntheticProvider),
        Arc::new(azureopenai::AzureOpenAIProvider),
        Arc::new(litellm::LiteLLMProvider),
        Arc::new(sub2api::Sub2ApiProvider),
        Arc::new(zai::ZaiProvider::default()),
        Arc::new(minimax::MiniMaxProvider::default()),
        Arc::new(wayfinder::WayfinderProvider),
        Arc::new(kilo::KiloProvider),
        Arc::new(perplexity::PerplexityProvider::default()),
        Arc::new(kimi::KimiProvider::default()),
        Arc::new(manus::ManusProvider::default()),
        Arc::new(abacus::AbacusProvider::default()),
        Arc::new(amp::AmpProvider::default()),
        Arc::new(commandcode::CommandCodeProvider::default()),
        Arc::new(stepfun::StepFunProvider::default()),
        Arc::new(t3chat::T3ChatProvider::default()),
        Arc::new(qoder::QoderProvider::default()),
        Arc::new(mimo::MiMoProvider::default()),
        Arc::new(augment::AugmentProvider::default()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProviderId;

    #[test]
    fn all_providers_matches_the_stable_provider_id_registry() {
        let ids = all_providers()
            .into_iter()
            .map(|provider| provider.descriptor().id)
            .collect::<Vec<_>>();
        assert_eq!(ids, ProviderId::ALL);
    }
}
