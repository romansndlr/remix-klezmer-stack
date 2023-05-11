import { User } from "@prisma/client";
import { redirect } from "@remix-run/node";
import { sessionStorage } from "./session.server";
import { db } from "./db.server";
import bcrypt from "bcryptjs";
import { badRequest } from "remix-utils";

export class AuthProvider {
  constructor(private request: Request) {}

  async session() {
    const cookie = this.request.headers.get("Cookie");

    return await sessionStorage.getSession(cookie);
  }

  async check(redirectTo: string) {
    const userId = await this.id();

    if (!userId) {
      const searchParams = new URLSearchParams([["redirectTo", redirectTo]]);

      throw redirect(`/login?${searchParams}`);
    }

    return userId;
  }

  async id(): Promise<User["id"] | undefined> {
    const session = await this.session();

    const userId = session.get("user-id");

    return userId;
  }

  async user() {
    const userId = await this.id();

    if (userId === undefined) return null;

    const user = await db.user.findFirstOrThrow({ where: { id: userId } });

    if (user) return user;

    throw await this.logout();
  }

  async create({
    email,
    password,
    remember = true,
  }: {
    email: User["email"];
    password: string;
    remember?: boolean;
  }) {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await db.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    const session = await this.session();

    session.set("user-id", user.id);

    return redirect("/", {
      headers: {
        "Set-Cookie": await sessionStorage.commitSession(session, {
          maxAge: remember
            ? 60 * 60 * 24 * 7 // 7 days
            : undefined,
        }),
      },
    });
  }

  async login({
    remember = true,
    email,
    password,
  }: {
    remember?: boolean;
    email: User["email"];
    password: string;
  }) {
    const userWithPassword = await db.user.findUnique({
      where: { email },
    });

    if (!userWithPassword || !userWithPassword.password) {
      throw badRequest({
        errors: { email: "Invalid email or password", password: null },
      });
    }

    const isValid = await bcrypt.compare(password, userWithPassword.password);

    if (!isValid) {
      throw badRequest({
        errors: { email: "Invalid email or password", password: null },
      });
    }

    const session = await this.session();

    session.set("user-id", userWithPassword.id);

    return redirect("/", {
      headers: {
        "Set-Cookie": await sessionStorage.commitSession(session, {
          maxAge: remember
            ? 60 * 60 * 24 * 7 // 7 days
            : undefined,
        }),
      },
    });
  }

  async logout() {
    return redirect("/", {
      headers: {
        "Set-Cookie": await sessionStorage.destroySession(await this.session()),
      },
    });
  }
}
