import { asArray } from "./asArray";
import { DuplicatePermissionError } from "./Errors";
import { Permission, PermissionPredicate, PermissionQuery } from "./Permission";

export type RolePredicate<UserType> = (u: UserType) => boolean;

export class Role<UserType> {
  permissions: Permission<UserType, unknown>[] = [];
  predicate?: RolePredicate<UserType>;

  appliesTo(user: UserType) {
    if (this.predicate) {
      return this.predicate(user);
    }

    return true;
  }

  grant<ObjectType extends unknown>(
    action: string,
    subject: any,
    params: {
      query?: PermissionQuery<UserType, ObjectType>;
      predicate?: PermissionPredicate<UserType, ObjectType>;
    } = {}
  ): void {
    // Fail if attempting to assign a permission for a subject
    // that has already been assigned.
    if (this.permissionExists(action, subject)) {
      throw new DuplicatePermissionError(
        `A permission for ${action} and ${subject.name} has already been defined`
      );
    }

    const { query, predicate } = params;
    const hasQuery = Boolean(query);
    const hasPredicate = Boolean(predicate);
    const permission = new Permission<UserType, ObjectType>(action, subject);

    if (hasQuery && hasPredicate) {
      permission.query = query;
      permission.predicate = predicate;
    } else if (hasQuery && !hasPredicate) {
      permission.query = query;

      if (action === "create") {
        // Create is a magic action which is valid
        // no matter the query, because it's not
        permission.predicate = () => true;
      } else {
        // Our default predicate if not provided
        // is simply a check for inclusion in the
        // result of calling query.
        permission.predicate = (u: UserType, subj: ObjectType) => {
          const res = query!!(u) ?? [];
          return res.includes(subj);
        };
      }
    } else if (!hasQuery && hasPredicate) {
      // Only a predicate provided
      permission.predicate = predicate;
    } else {
      // nothing was provided, so this is
      // just a truthy... thing
      permission.query = () => [];
      permission.predicate = () => true;
    }

    this.permissions.push(permission);
  }

  findPermission(
    action: string,
    subject: any
  ): Permission<UserType, unknown> | undefined {
    return this.permissions.find((permission) =>
      permission.matches(action, subject)
    );
  }

  permissionExists(action: string, subject: any): boolean {
    return Boolean(this.findPermission(action, subject));
  }

  _prepareActions(action: string | string[]): string[] {
    const actionArray = asArray<string>(action);
    const expandedActions = actionArray.flatMap(this._expandAction);

    return Array.from(new Set(expandedActions));
  }

  _expandAction(action: string): string | string[] {
    if (action === "rest") {
      return ["index", "new", "create", "show", "edit", "update", "delete"];
    } else if (action === "crud") {
      return ["create", "read", "update", "delete"];
    }

    return action;
  }
}
