"""Darco attack and vulnerability scanning template engine."""

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
    "execute_template_on_target",
    "generate_template_scaffold",
    "load_builtin_templates",
    "load_template",
    "load_template_from_string",
    "load_templates_from_dir",
    "run_template_scan",
]
