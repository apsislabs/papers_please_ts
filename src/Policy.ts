import { asArray } from "./asArray";
import {
  AccessDeniedError,
  DuplicateRoleError,
  MissingRoleError,
} from "./Errors";
import { Role } from "./Role";

export class Policy<
  UserType,
  RoleType,
  ActionType,
  SubjectType
> {
  roles: Map<RoleType, Role<UserType, ActionType, SubjectType>> = new Map();

  //
  // Add a role to this Policy.
  //
  // Roles are keyed by strings, and are insertion order
  // dependent --- meaning that Roles will be checked in
  // the order they are added to the Policy. This is an
  // important consideration because if your Policy
  // is defined in such a way that a User might fall into
  // multiple buckets, as soon as we find a Role that has
  // a matching Permission, we will return the result of
  // that Permission check --- and will not fall through
  // to subsequent matchiing Roles.
  //
  addRole(
    name: RoleType,
    predicate?: (u: UserType) => boolean
  ): Role<UserType, ActionType, SubjectType> {
    if (this.roles.has(name)) {
      throw new DuplicateRoleError(`Role ${name} has already been defined`);
    }

    const role = new Role<UserType, ActionType, SubjectType>();

    role.predicate = predicate ? predicate : () => true;
    this.roles.set(name, role);

    return role;
  }

  permit(
    name: RoleType | RoleType[],
    callback: (role: Role<UserType, ActionType, SubjectType>) => void
  ) {
    const nameArray = asArray<RoleType>(name);

    for (const roleName of nameArray) {
      if (this.roles.has(roleName)) {
        const role = this.roles.get(roleName);

        if (role) {
          callback(role);
        }
      } else {
        throw new MissingRoleError(`Role ${roleName} not found on Policy`);
      }
    }
  }

  can<K extends keyof SubjectType>(
    user: UserType,
    action: ActionType,
    subjectType: K,
    subject?: SubjectType[K]
  ): boolean {
    const rolesToCheck = this._applicableRoles(user);

    for (const role of rolesToCheck) {
      const permission = role.findPermission(action, subjectType);

      if (!permission) continue;

      // TODO: Proxy Permission Grants
      return permission.isGranted(user, action, subjectType, subject);
    }

    return false;
  }

  cannot<K extends keyof SubjectType>(
    user: UserType,
    action: ActionType,
    subjectType: K,
    subject: SubjectType[K]
  ): boolean {
    return !this.can(user, action, subjectType, subject);
  }

  authorize<K extends keyof SubjectType>(
    user: UserType,
    action: ActionType,
    subjectType: K,
    subject: SubjectType[K]
  ): void {
    if (this.cannot(user, action, subjectType, subject)) {
      throw new AccessDeniedError(
        `${action} is not permitted on ${subject} for ${user}`
      );
    }
  }

  queryFor<K extends keyof SubjectType>(
    user: UserType,
    action: ActionType,
    subjectType: keyof SubjectType
  ): SubjectType[K][] | null {
    const rolesToCheck = this._applicableRoles(user);

    for (const role of rolesToCheck) {
      const permission = role.findPermission(action, subjectType);
      if (!permission) continue;

      return permission.fetch(user);
    }

    return null;
  }

  _applicableRoles(user: UserType): Role<UserType, ActionType, SubjectType>[] {
    return Array.from(this.roles.values()).filter((role) =>
      role.appliesTo(user)
    );
  }
}
