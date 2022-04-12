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
  RoleType,
  ActionType,
  SubjectType
>(): Policy<UserType, RoleType, DefaultActionTypes | ActionType, SubjectType> =>
  new Policy<UserType, RoleType, DefaultActionTypes | ActionType , SubjectType>();
