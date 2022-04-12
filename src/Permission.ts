export type PermissionPredicate<
  UserType,
  ActionType,
  SubjectKeyType,
  SubjectType
> = (
  u: UserType,
  subject?: SubjectType,
  subjectType?: SubjectKeyType,
  action?: ActionType,
  permission?: Permission<UserType, ActionType, SubjectKeyType, SubjectType>
) => boolean;

export type PermissionQuery<UserType, SubjectType> = (
  u: UserType
) => SubjectType[];

export class Permission<UserType, ActionType, SubjectKeyType, SubjectType> {
  action: ActionType;
  subjectType: SubjectKeyType | null = null;
  query?: PermissionQuery<UserType, SubjectType>;
  predicate?: PermissionPredicate<
    UserType,
    ActionType,
    SubjectKeyType,
    SubjectType
  >;

  constructor(
    action: ActionType,
    subjectType: SubjectKeyType,
    query?: PermissionQuery<UserType, SubjectType>,
    predicate?: PermissionPredicate<
      UserType,
      ActionType,
      SubjectKeyType,
      SubjectType
    >
  ) {
    this.action = action;
    this.subjectType = subjectType;
    this.query = query;
    this.predicate = predicate;
  }

  matches(
    action: ActionType,
    subjectType: SubjectKeyType
  ): boolean {
    const matchesAction = action === this.action;
    const matchesSubject = subjectType === this.subjectType;

    return matchesAction && matchesSubject;
  }

  isGranted(
    u: UserType,
    action: ActionType,
    subjectType: SubjectKeyType,
    subject?: SubjectType
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
