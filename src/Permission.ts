export type PermissionPredicate<
  UserType,
  ObjectType,
  ActionType extends string,
  SubjectType extends string
> = (
  u: UserType,
  subject?: ObjectType,
  subjectType?: SubjectType,
  action?: ActionType,
  permission?: Permission<UserType, ObjectType, ActionType, SubjectType>
) => boolean;

export type PermissionQuery<UserType, ObjectType> = (
  u: UserType
) => ObjectType[];

export class Permission<
  UserType,
  ObjectType,
  ActionType extends string,
  SubjectType extends string
> {
  action: ActionType;
  subjectType: SubjectType | null = null;
  query?: PermissionQuery<UserType, ObjectType>;
  predicate?: PermissionPredicate<
    UserType,
    ObjectType,
    ActionType,
    SubjectType
  >;

  constructor(
    action: ActionType,
    subjectType: SubjectType,
    query?: PermissionQuery<UserType, ObjectType>,
    predicate?: PermissionPredicate<
      UserType,
      ObjectType,
      ActionType,
      SubjectType
    >
  ) {
    this.action = action;
    this.subjectType = subjectType;
    this.query = query;
    this.predicate = predicate;
  }

  matches(action: ActionType, subjectType: SubjectType): boolean {
    const matchesAction = action === this.action;
    const matchesSubject = subjectType === this.subjectType;

    return matchesAction && matchesSubject;
  }

  isGranted(
    u: UserType,
    action: ActionType,
    subjectType: SubjectType,
    subject?: ObjectType
  ): boolean {
    if (this.predicate) {
      return this.predicate(u, subject, subjectType, action, this);
    }

    // In theory this is unreachable, but... you know...
    return false;
  }

  fetch(u: UserType): any[] | null {
    if (this.query) {
      return this.query(u);
    }

    return null;
  }
}
