import { Policy } from "./Policy";

type DefaultActionTypes = 'crud' | 'rest' | 'create' | 'read' |'update' |'delete';

export const createPolicy = <
  UserType,
  RoleType extends string,
  ActionType extends string,
  SubjectType extends string
>(): Policy<UserType, RoleType, ActionType | DefaultActionTypes, SubjectType> =>
  new Policy<UserType, RoleType, ActionType | DefaultActionTypes, SubjectType>();
