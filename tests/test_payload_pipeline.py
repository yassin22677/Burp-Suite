"""
Core payload path: ``RequestContextExtractor`` → retrieval / hybrid generation →
``LabPayloadValidator`` → rankers, plus Intruder export helpers (one file; was split across
multiple ``test_*`` modules).
"""

from __future__ import annotations

from types import SimpleNamespace

from src.context_extractor import ParameterLocation, RequestContextExtractor
from src.payload_generator import (
    EnrichedCsvSeedRetriever,
    GenerationRequest,
    HybridCandidateGenerator,
    RetrievedSeed,
)
from src.payload_ranker import HeuristicLexicalRanker, MultiFactorExplainableRanker
from src.payload_validator import (
    LabPayloadValidator,
    LabPayloadValidatorConfig,
    PayloadCandidate,
    Severity,
)


def _query_ctx() -> dict:
    """GET + query parameter so ``slot_context`` uses name= prefix (clearer for SQL/cmd)."""
    return {
        "request_id": "hybrid_chain_test",
        "method": "GET",
        "url": "https://lab.example/search",
        "parameters": [
            {"name": "q", "location": "query", "declared_type": "string"},
        ],
    }


def _seed(payload: str) -> RetrievedSeed:
    return RetrievedSeed(
        seed_id="t0",
        payload=payload,
        score=1.0,
        score_breakdown={"total_weighted_score": 1.0},
    )


def _chain_ids(family: str, payload: str, *, n_candidates: int = 12) -> set[str]:
    ctx = RequestContextExtractor().extract(_query_ctx())
    req = GenerationRequest(
        context=ctx,
        family=family,
        k_seeds=1,
        n_candidates=n_candidates,
        options={"random_seed": 0},
    )
    gen = HybridCandidateGenerator()
    out = gen.generate(req, [_seed(payload)])
    return {c.metadata["transform_chain_id"] for c in out}


def test_sql_adds_balance_dashes_and_c_prefix_plus_dashes() -> None:
    ids = _chain_ids("sql", "' OR 1=1")
    assert "slot_context+sql_balance_odd_quotes+sql_suffix_comment_dashes" in ids
    assert "slot_context+sql_prefix_comment_c_style+sql_suffix_comment_dashes" in ids


def test_xss_adds_script_then_pct_and_img_onerror_chain() -> None:
    ids = _chain_ids("xss", "alert(1)")
    assert "slot_context+xss_wrap_script_lowercase+xss_percent_encode_angles" in ids
    assert "slot_context+xss_img_onerror_wrapper" in ids
    assert any("img src=x onerror" in c.value for c in _cands("xss", "alert(1)"))


def test_encoded_attack_nested_percent_chain() -> None:
    ids = _chain_ids("encoded_attack", "UNION")
    assert "slot_context+enc_percent_prefix+enc_double_percent_prefix" in ids


def test_cmd_ampersand_chain() -> None:
    ids = _chain_ids("cmd", "whoami")
    assert "slot_context+cmd_ampersand_prefix" in ids
    c = next(
        c
        for c in _cands("cmd", "whoami")
        if c.metadata["transform_chain_id"] == "slot_context+cmd_ampersand_prefix"
    )
    assert c.value.startswith("&")


def test_other_trim_then_encode_and_full_encode_chains() -> None:
    ids = _chain_ids("other", "a||b")
    assert "slot_context+generic_trim_duplicate_separators+enc_percent_prefix" in ids
    assert "slot_context+enc_percent_full_string" in ids


def test_xss_img_onerror_skips_when_already_present() -> None:
    gen = HybridCandidateGenerator()
    ctx = RequestContextExtractor().extract(_query_ctx())
    req = GenerationRequest(
        context=ctx,
        family="xss",
        k_seeds=1,
        n_candidates=8,
        options={"random_seed": 0},
    )
    seed = _seed('<img src=x onerror=alert(1)>')
    out = gen.generate(req, [seed])
    assert any("xss_img_onerror_skip" in c.transforms for c in out)


def test_lab_validator_accepts_hybrid_candidates() -> None:
    """Ranking/validation modules unchanged; candidates still narrow to :class:`PayloadCandidate`."""
    ctx = RequestContextExtractor().extract(_query_ctx())
    req = GenerationRequest(
        context=ctx,
        family="xss",
        k_seeds=1,
        n_candidates=6,
        options={"random_seed": 0},
    )
    gen = HybridCandidateGenerator()
    cands = gen.generate(req, [_seed("x")])
    v = LabPayloadValidator()
    for c in cands:
        pc = c.to_payload_candidate()
        res = v.validate(pc, ctx)
        assert hasattr(res, "is_valid") and hasattr(res, "findings")


def _cands(family: str, payload: str):
    ctx = RequestContextExtractor().extract(_query_ctx())
    req = GenerationRequest(
        context=ctx,
        family=family,
        k_seeds=1,
        n_candidates=12,
        options={"random_seed": 0},
    )
    return HybridCandidateGenerator().generate(req, [_seed(payload)])


# --- EnrichedCsvSeedRetriever (merged from former test_seed_generator.py)


def test_retriever_respects_family_and_k_seeds(enriched_kb_path, lab_request_dict: dict) -> None:
    ctx = RequestContextExtractor().extract(lab_request_dict)
    retriever = EnrichedCsvSeedRetriever(enriched_kb_path)
    req = GenerationRequest(context=ctx, family="xss", k_seeds=1, n_candidates=4, options={"random_seed": 1})
    seeds = retriever.retrieve(req)
    assert len(seeds) == 1
    assert seeds[0].payload
    assert (seeds[0].row_metadata.get("kb_family") or "").lower() == "xss"
    assert seeds[0].score_breakdown


def test_retriever_returns_empty_for_missing_family(enriched_kb_path, lab_request_dict: dict) -> None:
    ctx = RequestContextExtractor().extract(lab_request_dict)
    retriever = EnrichedCsvSeedRetriever(enriched_kb_path)
    req = GenerationRequest(context=ctx, family="nosuchfamily", k_seeds=3, n_candidates=4)
    assert retriever.retrieve(req) == []


def test_hybrid_generator_emits_candidates_and_explanations(enriched_kb_path, lab_request_dict: dict) -> None:
    ctx = RequestContextExtractor().extract(lab_request_dict)
    retriever = EnrichedCsvSeedRetriever(enriched_kb_path)
    seeds = retriever.retrieve(
        GenerationRequest(context=ctx, family="xss", k_seeds=2, n_candidates=8, options={"random_seed": 0})
    )
    gen = HybridCandidateGenerator()
    req = GenerationRequest(context=ctx, family="xss", k_seeds=2, n_candidates=6, options={"random_seed": 0})
    cands = gen.generate(req, seeds)
    assert len(cands) >= 1
    first = cands[0]
    assert first.value
    assert first.family == "xss"
    assert first.explanation, "trace steps support thesis XAI narrative"
    step_names = [e.step for e in first.explanation]
    assert "retrieve_seed" in step_names


# --- Intruder export helpers (shared by lab arms + CLIs)


def test_sanitize_intruder_lines_normalizes_embedded_newlines() -> None:
    from src.payload_generator import sanitize_intruder_lines

    assert sanitize_intruder_lines(["a\nb", "x\r\ny"]) == ["a b", "x y"]


def test_write_ranked_generative_audit_csv_round_trip(tmp_path) -> None:
    from src.payload_generator import GenerativeCandidate, ExplanationStep, write_ranked_generative_audit_csv
    import pandas as pd

    c = GenerativeCandidate(
        value="<x>",
        family="xss",
        transforms=["t1"],
        retrieval_ids=["s0"],
        explanation=[ExplanationStep(step="s", detail="d", data={})],
        rank_score=1.0,
        rank_explanation={"k": 1.0},
        metadata={"m": 2},
    )
    p = tmp_path / "audit.csv"
    write_ranked_generative_audit_csv(p, [c])
    df = pd.read_csv(p)
    assert len(df) == 1
    assert df.loc[0, "payload"] == "<x>"
    assert df.loc[0, "family"] == "xss"


# --- RequestContextExtractor


def test_extractor_preserves_request_id_and_method(lab_request_dict: dict) -> None:
    ex = RequestContextExtractor()
    ctx = ex.extract(lab_request_dict)
    assert ctx.request_id == "test_ctx_01"
    assert ctx.method == "POST"
    assert "search" in ctx.path


def test_extractor_sorts_parameter_tags_deterministically() -> None:
    raw = {
        "url": "https://example.com/x",
        "parameters": [
            {"name": "zeta", "location": "query"},
            {"name": "alpha", "location": "query"},
        ],
    }
    ctx = RequestContextExtractor().extract(raw)
    names = [p.name for p in ctx.parameter_tags]
    assert names == ["alpha", "zeta"]


def test_extractor_builds_url_from_split_fields() -> None:
    raw = {
        "method": "get",
        "host": "lab.local",
        "path": "/status",
        "protocol": "https",
    }
    ctx = RequestContextExtractor().extract(raw)
    assert ctx.url.startswith("https://lab.local")
    assert ctx.path == "/status"
    assert ctx.method == "GET"


def test_parameter_location_synonyms() -> None:
    raw = {
        "url": "https://e.com/",
        "parameters": [{"name": "p", "location": "body_form"}],
    }
    ctx = RequestContextExtractor().extract(raw)
    assert ctx.parameter_tags[0].location == ParameterLocation.BODY_FORM


# --- LabPayloadValidator


def _lab_val_ctx() -> object:
    return RequestContextExtractor().extract({"url": "https://lab/x", "method": "POST"})


def test_empty_payload_is_invalid() -> None:
    v = LabPayloadValidator()
    r = v.validate(PayloadCandidate(value="", source_label="t"), _lab_val_ctx())
    assert r.is_valid is False
    assert any(f.code == "ERR_EMPTY_PAYLOAD" for f in r.findings)


def test_simple_alphanumeric_payload_is_valid() -> None:
    v = LabPayloadValidator()
    r = v.validate(PayloadCandidate(value="or 1=1", source_label="t"), _lab_val_ctx())
    assert r.is_valid is True
    assert not any(f.severity == Severity.ERROR for f in r.findings)


def test_null_byte_rejected_when_configured() -> None:
    cfg = LabPayloadValidatorConfig(forbid_null_byte=True)
    v = LabPayloadValidator(cfg)
    r = v.validate(PayloadCandidate(value="a\x00b", source_label="t"), _lab_val_ctx())
    assert r.is_valid is False
    assert any(f.code == "ERR_NULL_BYTE" for f in r.findings)


def test_oversize_payload_rejected() -> None:
    cfg = LabPayloadValidatorConfig(max_payload_chars=4)
    v = LabPayloadValidator(cfg)
    r = v.validate(PayloadCandidate(value="12345", source_label="t"), _lab_val_ctx())
    assert r.is_valid is False
    assert any(f.code == "ERR_OVERSIZED" for f in r.findings)


# --- payload_ranker


def _rankable(value: str, family: str = "xss", transforms: list | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        value=value,
        family=family,
        transforms=transforms or ["xss_wrap_script_lowercase"],
        metadata={},
        rank_score=None,
        rank_explanation=None,
    )


def test_heuristic_ranker_orders_by_score() -> None:
    ctx = RequestContextExtractor().extract({"url": "https://lab/x"})
    a = _rankable("a")
    b = _rankable("x" * 120)
    ranker = HeuristicLexicalRanker(target_len=120)
    out = ranker.rank([a, b], ctx)
    assert out[0].rank_score is not None and out[1].rank_score is not None
    assert out[0].rank_score >= out[1].rank_score
    assert "length_term" in (out[0].rank_explanation or {})


def test_multifactor_ranker_sets_weighted_breakdown() -> None:
    ctx = RequestContextExtractor().extract(
        {"url": "https://lab.example/api/items/search", "parameters": [{"name": "q", "location": "query"}]}
    )
    c1 = _rankable("qqq unrelated", transforms=["generic_trim_noop"])
    c2 = _rankable("search items payload", transforms=["xss_event_handler_attr_shape"])
    ranker = MultiFactorExplainableRanker()
    out = ranker.rank([c1, c2], ctx)
    assert out[0].rank_explanation is not None
    keys = out[0].rank_explanation.keys()
    assert "weighted_context_compat" in keys
    assert "weighted_transform_alignment" in keys
