import { Policy } from "./Policy";

export const createPolicy = <UserType>(): Policy<UserType> => new Policy<UserType>();
