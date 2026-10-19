"""FastMCP gateway server factory and lifecycle assembler."""

from pathlib import Path
from fastmcp import FastMCP

from veilgate.config.policy_loader import PolicyLoader
from veilgate.config.policy_models import VeilgatePolicy
from veilgate.config.settings import VeilgateSettings
from veilgate.middleware.context_middleware import VeilgateContextMiddleware
from veilgate.pipeline import FirewallPipeline
from veilgate.repositories.approval_repo import ApprovalRepository
from veilgate.repositories.audit_repo import AuditRepository
from veilgate.repositories.catalog_repo import CatalogRepository
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.session_repo import SessionRepository
from veilgate.repositories.stash_repo import StashRepository
from veilgate.repositories.vault_repo import VaultRepository
from veilgate.security.crypto import VaultCrypto, resolve_master_key
from veilgate.services.acl_service import AclService
from veilgate.services.approval_service import ApprovalService
from veilgate.services.audit_service import AuditService
from veilgate.services.catalog_service import CatalogService
from veilgate.services.diet_service import DietService
from veilgate.services.explain_service import ExplainService
from veilgate.services.minimizer_service import MinimizerService
from veilgate.services.taint_service import TaintService
from veilgate.services.tokenizer_service import TokenizerService
from veilgate.services.upstream_registry import UpstreamRegistry
from veilgate.utils.logging_utils import setup_logger

logger = setup_logger("veilgate.gateway")


async def create_gateway_pipeline(
    settings: VeilgateSettings,
    policy: VeilgatePolicy | None = None,
    policy_loader: PolicyLoader | None = None,
) -> tuple[FirewallPipeline, DatabaseManager]:
    """Assemble all persistence repositories and pipeline services."""
    # 1. Database
    db_manager = DatabaseManager(settings.db_path)
    await db_manager.initialize()

    # 2. Cryptographic master key and vault crypto
    master_key_b64 = settings.master_key.get_secret_value() if settings.master_key else None
    master_key = resolve_master_key(master_key_b64)
    crypto = VaultCrypto(master_key)

    # 3. Policy loader and resolved policy
    loader = policy_loader or PolicyLoader(
        policy_path=settings.policy_path,
        learned_policy_path=settings.learned_policy_path,
    )
    resolved_policy = policy or loader.load()

    # 4. Repositories
    session_repo = SessionRepository(db_manager)
    vault_repo = VaultRepository(db_manager, crypto)
    catalog_repo = CatalogRepository(db_manager)
    audit_repo = AuditRepository(db_manager)
    approval_repo = ApprovalRepository(db_manager)
    stash_repo = StashRepository(db_manager)

    # 5. Services
    acl_service = AclService(resolved_policy)
    catalog_service = CatalogService(catalog_repo, resolved_policy)
    taint_service = TaintService(vault_repo, resolved_policy)
    tokenizer_service = TokenizerService(vault_repo)
    minimizer_service = MinimizerService(tokenizer_service, stash_repo, resolved_policy)
    diet_service = DietService(resolved_policy.diet)
    approval_service = ApprovalService(
        approval_repo=approval_repo,
        policy_loader=loader,
        timeout_seconds=settings.approval_timeout_seconds,
        dev_mode=settings.dev_mode,
    )
    audit_service = AuditService(audit_repo)
    upstream_registry = UpstreamRegistry(
        policy=resolved_policy,
        default_timeout_seconds=settings.upstream_timeout_seconds,
    )

    # 6. Pipeline
    pipeline = FirewallPipeline(
        session_repo=session_repo,
        catalog_repo=catalog_repo,
        stash_repo=stash_repo,
        acl_service=acl_service,
        catalog_service=catalog_service,
        taint_service=taint_service,
        minimizer_service=minimizer_service,
        diet_service=diet_service,
        approval_service=approval_service,
        audit_service=audit_service,
        upstream_registry=upstream_registry,
    )

    return pipeline, db_manager


def create_gateway_server(
    settings: VeilgateSettings,
    pipeline: FirewallPipeline,
) -> FastMCP:
    """Create FastMCP server configured with VeilgateContextMiddleware."""
    server = FastMCP(name="Veilgate")
    middleware = VeilgateContextMiddleware(pipeline)
    server.add_middleware(middleware)
    return server
