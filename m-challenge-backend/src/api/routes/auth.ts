import { FastifyInstance } from 'fastify';
import bcrypt from 'bcryptjs';
import { prisma } from '../../config/database';
import { z } from 'zod';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  fullName: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export async function authRoutes(app: FastifyInstance) {
  // POST /api/auth/register
  app.post('/register', async (request, reply) => {
    const body = registerSchema.parse(request.body);
    const existing = await prisma.user.findUnique({ where: { email: body.email } });
    if (existing) return reply.status(409).send({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(body.password, 12);
    const user = await prisma.user.create({
      data: {
        email: body.email,
        passwordHash,
        fullName: body.fullName,
        role: 'BASIC_SCANS',
        plan: 'FREE',
        scansRemaining: 20,
      },
    });

    const token = app.jwt.sign({ id: user.id, email: user.email, role: user.role }, { expiresIn: '7d' });
    return { token, user: { id: user.id, email: user.email, fullName: user.fullName, role: user.role, plan: user.plan, scansRemaining: user.scansRemaining } };
  });

  // POST /api/auth/login
  app.post('/login', async (request, reply) => {
    const body = loginSchema.parse(request.body);
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    if (!user) return reply.status(401).send({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(body.password, user.passwordHash);
    if (!valid) return reply.status(401).send({ error: 'Invalid credentials' });

    const token = app.jwt.sign({ id: user.id, email: user.email, role: user.role }, { expiresIn: '7d' });
    return { token, user: { id: user.id, email: user.email, fullName: user.fullName, role: user.role, plan: user.plan, scansRemaining: user.scansRemaining } };
  });

  // GET /api/auth/whoami
  app.get('/whoami', { preHandler: [(app as any).optionalAuth] }, async (request) => {
    const user = (request as any).user;
    if (!user) return { user: null, isAuthenticated: false };
    const dbUser = await prisma.user.findUnique({ where: { id: user.id }, select: { id: true, email: true, fullName: true, role: true, plan: true, scansRemaining: true } });
    return { user: dbUser, isAuthenticated: true };
  });

  // GET /api/auth/client-ip
  app.get('/client-ip', async (request) => {
    const ip = request.headers['cf-connecting-ip'] as string
      || (request.headers['x-forwarded-for'] as string)?.split(',')[0]
      || request.headers['x-real-ip'] as string
      || request.ip
      || 'Unknown';
    return { ip: ip.trim() };
  });
}
