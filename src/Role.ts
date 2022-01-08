import { asArray } from "./asArray";
import { DuplicatePermissionError } from "./Errors";
import { Permission, PermissionPredicate, PermissionQuery } from "./Permission";

export type RolePredicate<UserType> = (u: UserType) => boolean;

export class Role<
  UserType,
  ActionType extends string,
  SubjectType extends string
> {
  permissions: Permission<UserType, any, ActionType, SubjectType>[] = [];
  predicate?: RolePredicate<UserType>;

  appliesTo(user: UserType) {
    if (this.predicate) {
      return this.predicate(user);
    }

    return true;
  }

  grant<ObjectType>(
    action: ActionType | ActionType[],
    subjectType: SubjectType,
    params: {
      query?: PermissionQuery<UserType, ObjectType>;
      predicate?: PermissionPredicate<
        UserType,
        ObjectType,
        ActionType,
        SubjectType
      >;
    } = {}
  ): void {
    const preparedActions = this._prepareActions(action);

    for (let preparedAction of preparedActions) {
      // Fail if attempting to assign a permission for a subject
      // that has already been assigned.
      if (this.permissionExists(preparedAction, subjectType)) {
        throw new DuplicatePermissionError(
          `A permission for ${preparedAction} and ${subjectType} has already been defined`
        );
      }

      const { query, predicate } = params;
      const hasQuery = Boolean(query);
      const hasPredicate = Boolean(predicate);
      const permission = new Permission<
        UserType,
        ObjectType,
        ActionType,
        SubjectType
      >(preparedAction, subjectType);

      if (hasQuery && hasPredicate) {
        permission.query = query;
        permission.predicate = predicate;
      } else if (hasQuery && !hasPredicate) {
        permission.query = query;

        if (preparedAction === "create") {
          // Create is a magic action which is valid
          // no matter the query, because it's not
          permission.predicate = () => true;
        } else {
          // Our default predicate if not provided
          // is simply a check for inclusion in the
          // result of calling query.

          // permission.predicate = (u: UserType, subj: ObjectType) => {
          //   const res = query!!(u) ?? [];
          //   return res.includes(subj);
          // };
          permission.predicate =  () => true;
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
  }

  findPermission(
    action: ActionType,
    subjectType: SubjectType
  ): Permission<UserType, unknown, ActionType, SubjectType> | undefined {
    return this.permissions.find((permission) =>
      permission.matches(action, subjectType)
    );
  }

  permissionExists(action: ActionType, subjectType: SubjectType): boolean {
    return Boolean(this.findPermission(action, subjectType));
  }

  _prepareActions(action: ActionType | ActionType[]): ActionType[] {
    const actionArray = asArray<ActionType>(action);
    const expandedActions = actionArray.flatMap(this._expandAction);

    return Array.from(new Set(expandedActions));
  }

  _expandAction(action: ActionType): ActionType | ActionType[] {
    if (action === "rest") {
      return [
        "index",
        "new",
        "create",
        "show",
        "edit",
        "update",
        "delete",
      ] as ActionType[];
    } else if (action === "crud") {
      return ["create", "read", "update", "delete"] as ActionType[];
    }

    return action;
  }
}
