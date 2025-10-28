"use server";


import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { verifyPassword, generateToken } from "@/lib/auth";

export async function POST(req: NextRequest) {
  try {
    const { email, password } = await req.json();

    if (!email || !password) {
      return NextResponse.json(
        { error: "Email and password are required" },
        { status: 400 }
      );
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    let isPremium = user.isPremium;
    if (user.isPremium && user.premiumExpiry && user.premiumExpiry < new Date()) {
      isPremium = false;
      await prisma.user.update({
        where: { id: user.id },
        data: { isPremium: false },
      });
    }

    const token = generateToken({
      userId: user.id,
      email: user.email,
      isPremium,
    });

    return NextResponse.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isPremium,
        premiumExpiry: user.premiumExpiry
          ? user.premiumExpiry.toISOString()
          : null,
      },
      token,
      message: "Login successful",
    });
  } catch (err) {
    console.error("Login error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
