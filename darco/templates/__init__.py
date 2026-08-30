"""Darco attack and vulnerability scanning template engine."""

from .custom import (
    get_extractor_type,
    get_matcher_type,
    register_extractor_type,
    register_matcher_type,
    registered_extractor_types,
    registered_matcher_types,
)
from .dsl import evaluate_dsl
from .engine import (
    execute_template_on_target,
    run_template_scan,
)
from .loader import (
    load_builtin_templates,
    load_template,
    load_template_from_string,
    load_templates_from_dir,
)
from .models import (
    AttackTemplate,
    TemplateExtractor,
    TemplateInfo,
    TemplateMatcher,
    TemplateMatchResult,
    TemplateRequest,
    TemplateScanReport,
)
from .scaffold import (
    generate_template_scaffold,
)

__all__ = [
    "AttackTemplate",
    "TemplateExtractor",
    "TemplateInfo",
    "TemplateMatchResult",
    "TemplateMatcher",
    "TemplateRequest",
    "TemplateScanReport",
    "evaluate_dsl",
    "execute_template_on_target",
    "generate_template_scaffold",
    "get_extractor_type",
    "get_matcher_type",
    "load_builtin_templates",
    "load_template",
    "load_template_from_string",
    "load_templates_from_dir",
    "register_extractor_type",
    "register_matcher_type",
    "registered_extractor_types",
    "registered_matcher_types",
    "run_template_scan",
]
