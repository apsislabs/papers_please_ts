import { createPolicy } from "../index";

class Post {
  isArchived: boolean = false;
}

class User {
  isSuper: boolean = false;
  isAdmin: boolean = false;
  isMember: boolean = false;

  posts(): Post[] {
    return [new Post(), new Post()];
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

const ap = createPolicy<User>();

const superRole = ap.addRole("super", (u) => u.isSuper === true);
const adminRole = ap.addRole("admin", (u) => u.isAdmin === true);
const memberRole = ap.addRole("member", (u) => u.isMember === true);
const guestRole = ap.addRole("guest");


// Super Permissions
superRole.grant("manage", User);

superRole.grant<User>("eat", User, {
  predicate: (u, subject) => u !== subject,
});

// Admin Permissions
adminRole.grant<User>("eat", User, {
  predicate: (u, subject) => u !== subject,
});


test("adds 1 + 2 to equal 3", () => {
  console.log(ap);

  const superUser = new User("super");
  const adminUser = new User("admin");

  expect(superUser.isSuper).toBe(true);

  expect(ap.can(superUser, "manage", User)).toBe(true);
  expect(ap.can(adminUser, "manage", User)).toBe(false);

  expect(ap.can(adminUser, "eat", adminUser)).toBe(false);
  expect(ap.can(adminUser, "eat", superUser)).toBe(true);

  
});
