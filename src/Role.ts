import { asArray } from "./asArray";
import { DuplicatePermissionError } from "./Errors";
import { Permission, PermissionPredicate, PermissionQuery } from "./Permission";

export type RolePredicate<UserType> = (u: UserType) => boolean;

export class Role<UserType, ActionType, SubjectType> {
  permissions: Permission<
    UserType,
    ActionType,
    keyof SubjectType,
    SubjectType[keyof SubjectType]
  >[] = [];
  predicate?: RolePredicate<UserType>;

  appliesTo(user: UserType) {
    if (this.predicate) {
      return this.predicate(user);
    }

    return true;
  }

  grant<K extends SubjectType[keyof SubjectType]>(
    action: ActionType | ActionType[],
    subjectType: keyof SubjectType,
    params: {
      query?: PermissionQuery<UserType, K>;
      predicate?: PermissionPredicate<
        UserType,
        ActionType,
        keyof SubjectType,
        K
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
        ActionType,
        keyof SubjectType,
        K
      >(preparedAction, subjectType);

      if (hasQuery && hasPredicate) {
        permission.query = query;
        permission.predicate = predicate;
      } else if (hasQuery && !hasPredicate) {
        permission.query = query;

        if (preparedAction === ("create" as unknown as ActionType)) {
          // Create is a magic action which is valid
          // no matter the query, because it's not
          permission.predicate = () => true;
        } else {
          // Our default predicate if not provided
          // is simply a check for inclusion in the
          // result of calling query.

          permission.predicate = (u: UserType, subject?: K) => {
            const res = query!!(u) ?? [];
            return res.includes(subject!!);
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

      this.permissions.push(
        permission as unknown as Permission<
          UserType,
          ActionType,
          keyof SubjectType,
          SubjectType[keyof SubjectType]
        >
      );
    }
  }

  findPermission(
    action: ActionType,
    subjectType: keyof SubjectType
  ):
    | Permission<
        UserType,
        ActionType,
        keyof SubjectType,
        SubjectType[keyof SubjectType]
      >
    | undefined {
    return this.permissions.find((permission) =>
      permission.matches(action, subjectType)
    );
  }

  permissionExists(
    action: ActionType,
    subjectType: keyof SubjectType
  ): boolean {
    return Boolean(this.findPermission(action, subjectType));
  }

  _prepareActions(action: ActionType | ActionType[]): ActionType[] {
    const actionArray = asArray<ActionType>(action);
    const expandedActions = actionArray.flatMap(this._expandAction);

    return Array.from(new Set(expandedActions));
  }

  _expandAction(action: ActionType): ActionType | ActionType[] {
    if (action === ("rest" as unknown as ActionType)) {
      return [
        "index",
        "new",
        "create",
        "show",
        "edit",
        "update",
        "delete",
      ] as unknown[] as ActionType[];
    } else if (action === ("crud" as unknown as ActionType)) {
      return [
        "create",
        "read",
        "update",
        "delete",
      ] as unknown[] as ActionType[];
    }

    return action;
  }
}
