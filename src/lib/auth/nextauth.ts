import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import prisma from '@/lib/db/prisma';
import bcrypt from 'bcryptjs';

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        loginId: { label: 'Login ID', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.loginId || !credentials?.password) return null;
        const id = credentials.loginId.trim();
        // Find by loginId OR email (backward compat)
        const user = await prisma.user.findFirst({
          where: {
            isActive: true,
            OR: [
              { loginId: id },
              { email: id.toLowerCase() },
            ],
          },
        });
        if (!user || !user.isActive) return null;
        const isValid = await bcrypt.compare(credentials.password, user.password);
        if (!isValid) return null;
        return { id: String(user.id), email: user.email, name: user.name, role: user.role, loginId: user.loginId };
      },
    }),
  ],
  session: { strategy: 'jwt', maxAge: 24 * 60 * 60 },
  callbacks: {
    async jwt({ token, user }: { token: any; user: any }) {
      if (user) { token.role = (user as any).role; token.id = user.id; token.loginId = (user as any).loginId; }
      return token;
    },
    async session({ session, token }: { session: any; token: any }) {
      if (session.user) {
        (session.user as any).role    = token.role;
        (session.user as any).id      = token.id;
        (session.user as any).loginId = token.loginId;
      }
      return session;
    },
  },
  pages: { signIn: '/login', error: '/login' },
  secret: process.env.NEXTAUTH_SECRET,
};
