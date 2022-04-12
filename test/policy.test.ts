import { createPolicy } from "../index";

// This is purely a testing convention
// so that we can implement a method
// on the Post class to get all the posts
// that have been created.
let postStore: Post[] = [];

class Post {
  isArchived: boolean = false;
  author: User;

  constructor(author: User, isArchived: boolean = false) {
    this.author = author;
    this.isArchived = isArchived;

    postStore.push(this);
  }

  all(): Post[] {
    return postStore;
  }
}

class User {
  isSuper: boolean = false;
  isAdmin: boolean = false;
  isMember: boolean = false;

  _posts: Post[];

  posts(): Post[] {
    return this._posts;
  }

  constructor(role: "super" | "admin" | "member" | "guest") {
    if (role === "super") {
      this.isSuper = true;
    } else if (role === "admin") {
      this.isAdmin = true;
    } else if (role === "member") {
      this.isMember = true;
    }

    this._posts = [new Post(this), new Post(this, true)];
  }
}

type RolesDef = "super" | "admin" | "member" | "guest";
type ActionsDef = "archive";
type SubjectsDef = {
  user: User;
  post: Post;
};

const ap = createPolicy<User, RolesDef, ActionsDef, SubjectsDef>();

const superRole = ap.addRole("super", (u) => u.isSuper === true);
const adminRole = ap.addRole("admin", (u) => u.isAdmin === true);
const memberRole = ap.addRole("member", (u) => u.isMember === true);
const guestRole = ap.addRole("guest");

// Super Permissions
superRole.grant("crud", "user");
superRole.grant(["crud", "archive"], "post");

// Admin Permissions
adminRole.grant(["crud", "archive"], "post");
adminRole.grant<User>("read", "user", {
  predicate: (u, subject) => u === subject,
});

// Member Permissions
memberRole.grant<User>("read", "user", {
  predicate: (u, subject) => u === subject,
});

// memberRole.grant("create", "post");
memberRole.grant<Post>("read", "post", {
  predicate: (u, post) =>
    Boolean(post && (post.author === u || !post.isArchived)),
});

memberRole.grant<Post>("update", "post", {
  query: (u) => {
    return u.posts();
  },
});

memberRole.grant<Post>("archive", "post", {
  query: (u) => u.posts().filter((p) => !p.isArchived),
  predicate: (u, post) => Boolean(post && (post.author === u && !post.isArchived)),
});

guestRole.grant<Post>("read", "post", {
  predicate: (u, post) => Boolean(post && !post.isArchived),
});

const superUser = new User("super");
const adminUser = new User("admin");
const memberUser = new User("member");
const guestUser = new User("guest");

describe("User Permissions", () => {
  test("sets create permissions as expected", () => {
    expect(ap.can(superUser, "create", "user")).toBe(true);
    expect(ap.can(adminUser, "create", "user")).toBe(false);
    expect(ap.can(memberUser, "create", "user")).toBe(false);
    expect(ap.can(guestUser, "create", "user")).toBe(false);
  });

  test("sets read permissions as expected", () => {
    expect(ap.can(superUser, "read", "user", adminUser)).toBe(true);
    expect(ap.can(superUser, "read", "user", adminUser)).toBe(true);
    expect(ap.can(superUser, "read", "user", memberUser)).toBe(true);
    expect(ap.can(superUser, "read", "user", guestUser)).toBe(true);

    expect(ap.can(adminUser, "read", "user", superUser)).toBe(false);
    expect(ap.can(adminUser, "read", "user", adminUser)).toBe(true);
    expect(ap.can(adminUser, "read", "user", memberUser)).toBe(false);
    expect(ap.can(adminUser, "read", "user", guestUser)).toBe(false);

    expect(ap.can(memberUser, "read", "user", superUser)).toBe(false);
    expect(ap.can(memberUser, "read", "user", adminUser)).toBe(false);
    expect(ap.can(memberUser, "read", "user", memberUser)).toBe(true);
    expect(ap.can(memberUser, "read", "user", guestUser)).toBe(false);

    expect(ap.can(guestUser, "read", "user", superUser)).toBe(false);
    expect(ap.can(guestUser, "read", "user", adminUser)).toBe(false);
    expect(ap.can(guestUser, "read", "user", memberUser)).toBe(false);
    expect(ap.can(guestUser, "read", "user", guestUser)).toBe(false);
  });

  test("sets update permissions as expected", () => {
    expect(ap.can(superUser, "update", "user", superUser)).toBe(true);
    expect(ap.can(superUser, "update", "user", adminUser)).toBe(true);
    expect(ap.can(superUser, "update", "user", memberUser)).toBe(true);
    expect(ap.can(superUser, "update", "user", guestUser)).toBe(true);

    expect(ap.can(adminUser, "update", "user", superUser)).toBe(false);
    expect(ap.can(adminUser, "update", "user", adminUser)).toBe(false);
    expect(ap.can(adminUser, "update", "user", memberUser)).toBe(false);
    expect(ap.can(adminUser, "update", "user", guestUser)).toBe(false);

    expect(ap.can(memberUser, "update", "user", superUser)).toBe(false);
    expect(ap.can(memberUser, "update", "user", adminUser)).toBe(false);
    expect(ap.can(memberUser, "update", "user", memberUser)).toBe(false);
    expect(ap.can(memberUser, "update", "user", guestUser)).toBe(false);

    expect(ap.can(guestUser, "update", "user", superUser)).toBe(false);
    expect(ap.can(guestUser, "update", "user", adminUser)).toBe(false);
    expect(ap.can(guestUser, "update", "user", memberUser)).toBe(false);
    expect(ap.can(guestUser, "update", "user", guestUser)).toBe(false);
  });

  test("sets delete permissions as expected", () => {
    expect(ap.can(superUser, "delete", "user", superUser)).toBe(true);
    expect(ap.can(superUser, "delete", "user", adminUser)).toBe(true);
    expect(ap.can(superUser, "delete", "user", memberUser)).toBe(true);
    expect(ap.can(superUser, "delete", "user", guestUser)).toBe(true);

    expect(ap.can(adminUser, "delete", "user", superUser)).toBe(false);
    expect(ap.can(adminUser, "delete", "user", adminUser)).toBe(false);
    expect(ap.can(adminUser, "delete", "user", memberUser)).toBe(false);
    expect(ap.can(adminUser, "delete", "user", guestUser)).toBe(false);

    expect(ap.can(memberUser, "delete", "user", superUser)).toBe(false);
    expect(ap.can(memberUser, "delete", "user", adminUser)).toBe(false);
    expect(ap.can(memberUser, "delete", "user", memberUser)).toBe(false);
    expect(ap.can(memberUser, "delete", "user", guestUser)).toBe(false);

    expect(ap.can(guestUser, "delete", "user", superUser)).toBe(false);
    expect(ap.can(guestUser, "delete", "user", adminUser)).toBe(false);
    expect(ap.can(guestUser, "delete", "user", memberUser)).toBe(false);
    expect(ap.can(guestUser, "delete", "user", guestUser)).toBe(false);
  });
});

describe("Post Permissions", () => {
  test("sets create permissions as expected", () => {
    expect(ap.can(superUser, "create", "post")).toBe(true);
  });

  test("sets read permissions as expected", () => {
    const [suPost, suArchivedPost] = superUser.posts();
    const [auPost, auArchivedPost] = adminUser.posts();
    const [muPost, muArchivedPost] = memberUser.posts();

    // A super user can read any post
    expect(ap.can<"post">(superUser, "read", "post", suPost)).toBe(true);
    expect(ap.can<"post">(superUser, "read", "post", auPost)).toBe(true);
    expect(ap.can<"post">(superUser, "read", "post", muPost)).toBe(true);
    expect(ap.can<"post">(superUser, "read", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "read", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "read", "post", muArchivedPost)).toBe(
      true
    );

    // An admin user can read any post
    expect(ap.can<"post">(adminUser, "read", "post", suPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "read", "post", auPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "read", "post", muPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "read", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "read", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "read", "post", muArchivedPost)).toBe(
      true
    );

    // A member can read any post that isn't archived,
    // and also their own archived posts.
    expect(ap.can(memberUser, "read", "post", suPost)).toBe(true);
    expect(ap.can(memberUser, "read", "post", auPost)).toBe(true);
    expect(ap.can(memberUser, "read", "post", muPost)).toBe(true);
    expect(ap.can(memberUser, "read", "post", suArchivedPost)).toBe(false);
    expect(ap.can(memberUser, "read", "post", auArchivedPost)).toBe(false);
    expect(ap.can(memberUser, "read", "post", muArchivedPost)).toBe(true);

    // A guest user can read any unarchived post
    expect(ap.can(guestUser, "read", "post", suPost)).toBe(true);
    expect(ap.can(guestUser, "read", "post", auPost)).toBe(true);
    expect(ap.can(guestUser, "read", "post", muPost)).toBe(true);
    expect(ap.can(guestUser, "read", "post", suArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "read", "post", auArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "read", "post", muArchivedPost)).toBe(false);
  });

  test("sets update permissions as expected", () => {
    const [suPost, suArchivedPost] = superUser.posts();
    const [auPost, auArchivedPost] = adminUser.posts();
    const [muPost, muArchivedPost] = memberUser.posts();

    // A super user can update any post
    expect(ap.can<"post">(superUser, "update", "post", suPost)).toBe(true);
    expect(ap.can<"post">(superUser, "update", "post", auPost)).toBe(true);
    expect(ap.can<"post">(superUser, "update", "post", muPost)).toBe(true);
    expect(ap.can<"post">(superUser, "update", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "update", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "update", "post", muArchivedPost)).toBe(
      true
    );

    // An admin user can update any post
    expect(ap.can<"post">(adminUser, "update", "post", suPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "update", "post", auPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "update", "post", muPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "update", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "update", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "update", "post", muArchivedPost)).toBe(
      true
    );

    // A member can update their own posts
    expect(ap.can<"post">(memberUser, "update", "post", suPost)).toBe(false);
    expect(ap.can<"post">(memberUser, "update", "post", auPost)).toBe(false);
    expect(ap.can<"post">(memberUser, "update", "post", muPost)).toBe(true);
    expect(ap.can<"post">(memberUser, "update", "post", suArchivedPost)).toBe(
      false
    );
    expect(ap.can<"post">(memberUser, "update", "post", auArchivedPost)).toBe(
      false
    );
    expect(ap.can<"post">(memberUser, "update", "post", muArchivedPost)).toBe(
      true
    );

    // A guest user cannot update any posts
    expect(ap.can(guestUser, "update", "post", suPost)).toBe(false);
    expect(ap.can(guestUser, "update", "post", auPost)).toBe(false);
    expect(ap.can(guestUser, "update", "post", muPost)).toBe(false);
    expect(ap.can(guestUser, "update", "post", suArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "update", "post", auArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "update", "post", muArchivedPost)).toBe(false);
  });

  test("sets delete permissions as expected", () => {
    const [suPost, suArchivedPost] = superUser.posts();
    const [auPost, auArchivedPost] = adminUser.posts();
    const [muPost, muArchivedPost] = memberUser.posts();

    // A super user can delete any post
    expect(ap.can<"post">(superUser, "delete", "post", suPost)).toBe(true);
    expect(ap.can<"post">(superUser, "delete", "post", auPost)).toBe(true);
    expect(ap.can<"post">(superUser, "delete", "post", muPost)).toBe(true);
    expect(ap.can<"post">(superUser, "delete", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "delete", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "delete", "post", muArchivedPost)).toBe(
      true
    );

    // An admin user can delete any post
    expect(ap.can<"post">(adminUser, "delete", "post", suPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "delete", "post", auPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "delete", "post", muPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "delete", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "delete", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "delete", "post", muArchivedPost)).toBe(
      true
    );

    // A member cannot delete any posts
    expect(ap.can<"post">(memberUser, "delete", "post", suPost)).toBe(false);
    expect(ap.can<"post">(memberUser, "delete", "post", auPost)).toBe(false);
    expect(ap.can<"post">(memberUser, "delete", "post", muPost)).toBe(false);
    expect(ap.can<"post">(memberUser, "delete", "post", suArchivedPost)).toBe(
      false
    );
    expect(ap.can<"post">(memberUser, "delete", "post", auArchivedPost)).toBe(
      false
    );
    expect(ap.can<"post">(memberUser, "delete", "post", muArchivedPost)).toBe(
      false
    );

    // A guest user cannot delete any posts
    expect(ap.can(guestUser, "delete", "post", suPost)).toBe(false);
    expect(ap.can(guestUser, "delete", "post", auPost)).toBe(false);
    expect(ap.can(guestUser, "delete", "post", muPost)).toBe(false);
    expect(ap.can(guestUser, "delete", "post", suArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "delete", "post", auArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "delete", "post", muArchivedPost)).toBe(false);
  });

  test("sets archive permissions as expected", () => {
    const [suPost, suArchivedPost] = superUser.posts();
    const [auPost, auArchivedPost] = adminUser.posts();
    const [muPost, muArchivedPost] = memberUser.posts();

    // A super user can archive any post
    expect(ap.can<"post">(superUser, "archive", "post", suPost)).toBe(true);
    expect(ap.can<"post">(superUser, "archive", "post", auPost)).toBe(true);
    expect(ap.can<"post">(superUser, "archive", "post", muPost)).toBe(true);
    expect(ap.can<"post">(superUser, "archive", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "archive", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(superUser, "archive", "post", muArchivedPost)).toBe(
      true
    );

    // An admin user can archive any post
    expect(ap.can<"post">(adminUser, "archive", "post", suPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "archive", "post", auPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "archive", "post", muPost)).toBe(true);
    expect(ap.can<"post">(adminUser, "archive", "post", suArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "archive", "post", auArchivedPost)).toBe(
      true
    );
    expect(ap.can<"post">(adminUser, "archive", "post", muArchivedPost)).toBe(
      true
    );

    // A member can archive their own unarchived posts
    expect(ap.can<"post">(memberUser, "archive", "post", suPost)).toBe(false);
    expect(ap.can<"post">(memberUser, "archive", "post", auPost)).toBe(false);
    expect(ap.can<"post">(memberUser, "archive", "post", muPost)).toBe(true);

    // A member cannot archive posts that are already archived
    expect(ap.can<"post">(memberUser, "archive", "post", suArchivedPost)).toBe(
      false
    );
    expect(ap.can<"post">(memberUser, "archive", "post", auArchivedPost)).toBe(
      false
    );
    expect(ap.can<"post">(memberUser, "archive", "post", muArchivedPost)).toBe(
      false
    );

    // A guest user cannot archive any posts
    expect(ap.can(guestUser, "archive", "post", suPost)).toBe(false);
    expect(ap.can(guestUser, "archive", "post", auPost)).toBe(false);
    expect(ap.can(guestUser, "archive", "post", muPost)).toBe(false);
    expect(ap.can(guestUser, "archive", "post", suArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "archive", "post", auArchivedPost)).toBe(false);
    expect(ap.can(guestUser, "archive", "post", muArchivedPost)).toBe(false);
  });
});
