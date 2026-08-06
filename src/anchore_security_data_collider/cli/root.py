import dataclasses
import enum
import logging
from typing import Any

import click
import yaml

from anchore_security_data_collider import __name__ as package_name
from anchore_security_data_collider.cli.config import Application
from anchore_security_data_collider.cli.data.commands import group as data_group


@click.option("--verbose", "-v", default=False, help="show logs", count=True)
@click.group(help="Tool for performing various Anchore security data curation tasks")
@click.version_option(package_name=package_name, message="%(prog)s %(version)s")
@click.pass_context
def root(ctx: click.core.Context, verbose: bool) -> None:
    import logging.config  # noqa: PLC0415

    ctx.obj = Application()
    log_level = ctx.obj.log.level
    if verbose == 1:
        log_level = "DEBUG"
    elif verbose >= 2:
        log_level = "TRACE"

    if ctx.obj.log.slim:
        timestamp_format = ""
        level_format = ""
    else:
        timestamp_format = "%(asctime)s "
        if not ctx.obj.log.show_timestamp:
            timestamp_format = ""

        level_format = "[%(levelname)-5s] "
        if not ctx.obj.log.show_level:
            level_format = ""

    log_format = f"%(log_color)s{timestamp_format}{level_format}%(message)s"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    "()": "colorlog.ColoredFormatter",  # colored output
                    # [%(module)s.%(funcName)s]
                    "format": log_format,
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                    "log_colors": {
                        "TRACE": "purple",
                        "DEBUG": "cyan",
                        "INFO": "reset",
                        "WARNING": "yellow",
                        "ERROR": "red",
                        "CRITICAL": "red,bg_white",
                    },
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    "class": "colorlog.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "": {  # root logger
                    "handlers": ["default"],
                    "level": log_level,
                },
            },
        },
    )


@root.command(name="config", help="show the application config")
@click.pass_obj
def show_config(cfg: Application) -> None:
    logging.info("showing application config")

    class IndentDumper(yaml.Dumper):
        def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
            return super().increase_indent(flow, False)

    def enum_asdict_factory(data: list[tuple[str, Any]]) -> dict[Any, Any]:
        def convert_value(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            return obj

        return {k: convert_value(v) for k, v in data}

    cfg_dict = dataclasses.asdict(cfg, dict_factory=enum_asdict_factory)
    print(yaml.dump(cfg_dict, Dumper=IndentDumper, default_flow_style=False))

root.add_command(cmd=data_group)
