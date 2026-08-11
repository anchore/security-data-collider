import enum


class DeploymentEnvironment(enum.StrEnum):
    DEVELOPMENT = enum.auto()
    INTEGRATION = enum.auto()
    PRODUCTION = enum.auto()
