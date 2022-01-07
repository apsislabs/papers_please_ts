export type PermissionPredicate<UserType, ObjectType> = (
  u: any,
  subject: any,
  action: string,
  permission: Permission<UserType, ObjectType>
) => boolean;

export type PermissionQuery<UserType, ObjectType> = (
  u: UserType
) => ObjectType[];

export class Permission<UserType, ObjectType> {
  action: string;
  subject: any = null;
  query?: PermissionQuery<UserType, ObjectType>;
  predicate?: PermissionPredicate<UserType, ObjectType>;

  constructor(
    action: string,
    subject: any,
    query?: PermissionQuery<UserType, ObjectType>,
    predicate?: PermissionPredicate<UserType, ObjectType>
  ) {
    this.action = action;
    this.subject = subject;
    this.query = query;
    this.predicate = predicate;
  }

  matches(action: string, subject: any): boolean {
    const matchesAction = action === this.action;
    const matchesSubject =
      subject == this.subject || subject instanceof this.subject;

    return matchesAction && matchesSubject;
  }

  isGranted(u: UserType, subj: any, action: string): boolean {
    if (this.predicate) {
      return this.predicate(u, subj, action, this);
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
