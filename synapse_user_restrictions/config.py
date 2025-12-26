import enum
import re
from enum import Enum
from typing import Any, Dict, Iterable, List, Pattern, Set, TypeVar, cast

import attr

ConfigDict = Dict[str, Any]

def check_and_compile_regex(value: Any) -> Pattern[str]:
    """
    Given a value from the configuration, which is validated to be a string,
    compiles and returns a regular expression.
    """
    if not isinstance(value, str):
        raise ValueError("Regex patterns should be specified as strings.")

    try:
        return re.compile(value)
    except re.error as e:
        raise ValueError(f"Invalid regex '{value}': {e.msg}")

def check_all_permissions_understood(permissions: Iterable[str]) -> None:
    """
    Checks that all the permissions contained in the list of permissions are
    ones that we understand and recognise.
    """
    for permission in permissions:
        if permission not in ALL_UNDERSTOOD_PERMISSIONS:
            nice_list_of_understood_permissions = ", ".join(
                sorted(ALL_UNDERSTOOD_PERMISSIONS)
            )
            raise ValueError(
                f"{permission!r} is not a permission recognised "
                f"by the User Restrictions module; "
                f"try one of: {nice_list_of_understood_permissions}"
            )

T = TypeVar("T")

def check_list_elements_are_strings(
    input: List[Any], failure_message: str
) -> List[str]:
    """
    Checks that all elements in a list are of the specified type, casting it upon
    success.
    """
    for ele in input:
        if not isinstance(ele, str):
            raise ValueError(failure_message)

    return cast(List[str], input)

class RuleResult(Enum):
    NoDecision = enum.auto()
    Allow = enum.auto()
    Deny = enum.auto()

@attr.s(auto_attribs=True, frozen=True, slots=True)
class RegexMatchRule:
    """
    A single rule that performs a regex match.
    """
    match: Pattern[str]
    allow: Set[str]
    deny: Set[str]

    def apply(self, user_id: str, permission: str) -> RuleResult:
        """
        Applies a regular expression match rule, returning a rule result.
        """
        if not self.match.fullmatch(user_id):
            return RuleResult.NoDecision
        if permission in self.allow:
            return RuleResult.Allow
        if permission in self.deny:
            return RuleResult.Deny
        return RuleResult.NoDecision

    @staticmethod
    def from_config(rule: ConfigDict) -> "RegexMatchRule":
        if "match" not in rule:
            raise ValueError("Rules must have a 'match' field")
        match_pattern = check_and_compile_regex(rule["match"])

        if "allow" in rule:
            if not isinstance(rule["allow"], list):
                raise ValueError("Rule's 'allow' field must be a list.")
            allow_list = check_list_elements_are_strings(
                rule["allow"], "Rule's 'allow' field must be a list of strings."
            )
            check_all_permissions_understood(allow_list)
        else:
            allow_list = []

        if "deny" in rule:
            if not isinstance(rule["deny"], list):
                raise ValueError("Rule's 'deny' field must be a list.")
            deny_list = check_list_elements_are_strings(
                rule["deny"], "Rule's 'deny' field must be a list of strings."
            )
            check_all_permissions_understood(deny_list)
        else:
            deny_list = []

        return RegexMatchRule(
            match=match_pattern, allow=set(allow_list), deny=set(deny_list)
        )

@attr.s(auto_attribs=True, frozen=True, slots=True)
class UserRestrictionsModuleConfig:
    """
    The root-level configuration.
    """
    rules: List[RegexMatchRule]
    default_deny: Set[str]
    local_homeservers: Set[str]

    @staticmethod
    def from_config(config_dict: ConfigDict) -> "UserRestrictionsModuleConfig":
        if "rules" not in config_dict:
            raise ValueError("'rules' list not specified in module configuration.")
        if not isinstance(config_dict["rules"], list):
            raise ValueError("'rules' should be a list.")

        rules = []
        for index, rule in enumerate(config_dict["rules"]):
            if not isinstance(rule, dict):
                raise ValueError(
                    f"Rules should be dicts. "
                    f"Rule number {index + 1} is not (found: {type(rule).__name__})."
                )
            rules.append(RegexMatchRule.from_config(rule))

        default_deny = config_dict.get("default_deny")
        if default_deny is not None:
            if not isinstance(default_deny, list):
                raise ValueError("'default_deny' should be a list (or unspecified).")
            check_list_elements_are_strings(
                default_deny, "'default_deny' should be a list of strings."
            )
            check_all_permissions_understood(default_deny)
            default_deny_set = set(default_deny)
        else:
            default_deny_set = set()

        local_hs = config_dict.get("local_homeservers")
        if local_hs is not None:
            if not isinstance(local_hs, list):
                raise ValueError("'local_homeservers' should be a list (or unspecified).")
            local_hs_list = check_list_elements_are_strings(
                local_hs, "'local_homeservers' should be a list of strings."
            )
            local_homeservers_set = {hs.lower() for hs in local_hs_list}
        else:
            local_homeservers_set = set()

        return UserRestrictionsModuleConfig(
            rules=rules,
            default_deny=default_deny_set,
            local_homeservers=local_homeservers_set,
        )

INVITE = "invite"
CREATE_ROOM = "create_room"
RECEIVE_INVITES = "receive_invites"
RECEIVE_ALL_INVITES = "receive_all_invites"
INVITE_ALL = "invite_all"
JOIN_ROOM = "join_room"
ALL_UNDERSTOOD_PERMISSIONS = frozenset({
    INVITE, CREATE_ROOM, RECEIVE_INVITES, RECEIVE_ALL_INVITES, INVITE_ALL, JOIN_ROOM
})
