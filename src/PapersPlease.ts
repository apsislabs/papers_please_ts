import { Policy } from "./Policy";

type RestActionTypes =
  | "rest"
  | "index"
  | "new"
  | "create"
  | "show"
  | "edit"
  | "update"
  | "delete";

type CrudActionTypes = "crud" | "create" | "read" | "update" | "delete";

type DefaultActionTypes = CrudActionTypes | RestActionTypes;

export const createPolicy = <
  UserType,
  RoleType extends string,
  ActionType extends string,
  SubjectType extends string
>(): Policy<UserType, RoleType, ActionType | DefaultActionTypes, SubjectType> =>
  new Policy<
    UserType,
    RoleType,
    ActionType | DefaultActionTypes,
    SubjectType
  >();
