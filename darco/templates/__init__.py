"""Darco attack and vulnerability scanning template engine."""

from .models import (
    AttackTemplate,
    TemplateExtractor,
    TemplateInfo,
    TemplateMatchResult,
    TemplateMatcher,
    TemplateRequest,
    TemplateScanReport,
)
from .loader import (
    load_template,
    load_template_from_string,
    load_templates_from_dir,
    load_builtin_templates,
)
from .engine import (
    execute_template_on_target,
    run_template_scan,
)
from .scaffold import (
    generate_template_scaffold,
)

__all__ = [
    "AttackTemplate",
    "TemplateInfo",
    "TemplateMatcher",
    "TemplateExtractor",
    "TemplateRequest",
    "TemplateMatchResult",
    "TemplateScanReport",
    "load_template",
    "load_template_from_string",
    "load_templates_from_dir",
    "load_builtin_templates",
    "execute_template_on_target",
    "run_template_scan",
    "generate_template_scaffold",
]
