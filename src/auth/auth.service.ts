import { ConfigService } from '@nestjs/config';
import { AuthDto } from './dto/auth.dto';
import { PrismaService } from './../prisma/prisma.service';
import { ForbiddenException, Injectable } from "@nestjs/common";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {}

    async signup(authDto: AuthDto) {
        // generate the password hash
        const hash = await argon.hash(authDto.password);
        // save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: authDto.email,
                    hash,
                },
            });
    
            delete user.hash;
    
            // return the saved user
            return user;
        }
        catch(error)
        {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === "P2002") {
                    throw new ForbiddenException('Credentials taken');
                }
            }
            throw error;
        }
    }

    async signin(authDto: AuthDto) {
        // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: authDto.email,
            }
        });

        // if user does not exists throw exception
        if (!user) throw new ForbiddenException("Credentials incorrect.");
        // compare password
        const pwMatches = await argon.verify(user.hash, authDto.password);

        // if password is incorrect throw exception
        if (!pwMatches) throw new ForbiddenException('Credentials incorrect.');
        return this.signToken(user.id, user.email);
    }

    async signToken(userId: number, email: string): Promise<{access_token: string}> {
        const payload = {
            sub: userId,
            email
        }

        const secret = this.config.get("JWT_SECRET");

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret,
        });

        return {
            access_token: token,
        };
    }
}

