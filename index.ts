import { createPolicy } from "./src/PapersPlease";
import { Permission } from "./src/Permission";
import { Policy } from "./src/Policy";
import { Role } from "./src/Role";
import {
  PapersPleaseError,
  AccessDeniedError,
  InvalidGrantError,
  DuplicateRoleError,
  MissingRoleError,
  DuplicatePermissionError,
  InvalidPermissionError,
  DuplicateScopeError,
  InvalidScopeError,
} from "./src/Errors";

export {
  createPolicy,
  Policy,
  Role,
  Permission,
  PapersPleaseError,
  AccessDeniedError,
  InvalidGrantError,
  DuplicateRoleError,
  MissingRoleError,
  DuplicatePermissionError,
  InvalidPermissionError,
  DuplicateScopeError,
  InvalidScopeError,
};
