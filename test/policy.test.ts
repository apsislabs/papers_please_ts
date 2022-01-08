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

  posts(): Post[] {
    return [new Post(this), new Post(this, true)];
  }

  constructor(role: "super" | "admin" | "member" | "guest") {
    if (role === "super") {
      this.isSuper = true;
    } else if (role === "admin") {
      this.isAdmin = true;
    } else if (role === "member") {
      this.isMember = true;
    }
  }
}

type RolesDef = 'super' | 'admin' | 'member' | 'gues';
type ActionsDef = 'archive';
type SubjectsDef = 'user' | 'post';

const ap = createPolicy<User, RolesDef, ActionsDef, SubjectsDef>();

const superRole = ap.addRole("super", (u) => u.isSuper === true);
const adminRole = ap.addRole("admin", (u) => u.isAdmin === true);
const memberRole = ap.addRole("member", (u) => u.isMember === true);
const guestRole = ap.addRole("guest");

// Super Permissions
superRole.grant("crud", "user");
superRole.grant("crud", "post");
superRole.grant("archive", "post");

// Admin Permissions
adminRole.grant("crud", "post");
adminRole.grant("archive", "post");
adminRole.grant<User>("read", "user", {
  predicate: (u, subject) => u === subject,
});

// Member Permissions
memberRole.grant<User>("read", "user", {
  predicate: (u, subject) => u === subject,
});

memberRole.grant("create", "post");
memberRole.grant<Post>("read", "post", {
  predicate: (u, post) => Boolean(post && (post.author === u || !post.isArchived)),
});
memberRole.grant<Post>("update", "post", { query: (u) => u.posts() });

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
    expect(ap.can(superUser, "read", "user", superUser)).toBe(true);
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

// describe("Post Permissions", () => {
//   test("sets create permissions as expected", () => {
//     expect(ap.can(superUser, "create", "post")).toBe(true);
//     expect(ap.can(adminUser, "create", "post")).toBe(true);
//     expect(ap.can(memberUser, "create", "post")).toBe(true);
//     expect(ap.can(guestUser, "create", "post")).toBe(false);
//   });

//   test("sets read permissions as expected", () => {
//     const [suPost, suArchivedPost] = superUser.posts();
//     const [auPost, auArchivedPost] = adminUser.posts();
//     const [muPost, muArchivedPost] = memberUser.posts();

//     // A super user can read any post
//     expect(ap.can(superUser, "read", suPost)).toBe(true);
//     expect(ap.can(superUser, "read", auPost)).toBe(true);
//     expect(ap.can(superUser, "read", muPost)).toBe(true);
//     expect(ap.can(superUser, "read", suArchivedPost)).toBe(true);
//     expect(ap.can(superUser, "read", auArchivedPost)).toBe(true);
//     expect(ap.can(superUser, "read", muArchivedPost)).toBe(true);

//     // An admin user can read any post
//     expect(ap.can(adminUser, "read", suPost)).toBe(true);
//     expect(ap.can(adminUser, "read", auPost)).toBe(true);
//     expect(ap.can(adminUser, "read", muPost)).toBe(true);
//     expect(ap.can(adminUser, "read", suArchivedPost)).toBe(true);
//     expect(ap.can(adminUser, "read", auArchivedPost)).toBe(true);
//     expect(ap.can(adminUser, "read", muArchivedPost)).toBe(true);

//     // A member can read any post that isn't archived,
//     // and also their own archived posts.
//     expect(ap.can(memberUser, "read", suPost)).toBe(true);
//     expect(ap.can(memberUser, "read", auPost)).toBe(true);
//     expect(ap.can(memberUser, "read", muPost)).toBe(true);
//     expect(ap.can(memberUser, "read", suArchivedPost)).toBe(false);
//     expect(ap.can(memberUser, "read", auArchivedPost)).toBe(false);
//     expect(ap.can(memberUser, "read", muArchivedPost)).toBe(true);

//     // A guest user can read any unarchived post
//     expect(ap.can(guestUser, "read", suPost)).toBe(true);
//     expect(ap.can(guestUser, "read", auPost)).toBe(true);
//     expect(ap.can(guestUser, "read", muPost)).toBe(true);
//     expect(ap.can(guestUser, "read", suArchivedPost)).toBe(false);
//     expect(ap.can(guestUser, "read", auArchivedPost)).toBe(false);
//     expect(ap.can(guestUser, "read", muArchivedPost)).toBe(false);
//   });
// });
