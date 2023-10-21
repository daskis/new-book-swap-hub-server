import {ForbiddenException, Inject, Injectable} from '@nestjs/common';
import {PrismaService} from '@prisma/prisma.service';
import {Role, User} from '@prisma/client';
import {genSaltSync, hashSync} from 'bcrypt';
import {JwtPayload} from "@auth/interfaces";
import {CACHE_MANAGER} from "@nestjs/cache-manager";
import {Cache} from "cache-manager";
import {ConfigService} from "@nestjs/config";
import {convertToSecondsUtil} from "@common/utils";
import {CurrentUser} from "@common/decorators";

@Injectable()
export class UserService {
    constructor(
        private readonly prismaService: PrismaService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private readonly configService: ConfigService
    ) {
    }

    async save(user: Partial<User>) {
        const hashedPassword = user?.password ? this.hashPassword(user.password) : null;
        // const savedUser = await this.prismaService.user.create({
        //     data: {
        //         email: user.email,
        //         password: hashedPassword,
        //         roles: ['USER'],
        //         provider: user.provider
        //     },
        // });
        const savedUser = await this.prismaService.user.upsert({
            where: {
                email: user.email
            },
            update: {
                password: hashedPassword,
                provider: user?.provider,
                roles: user.roles
            },
            create: {
                email: user.email,
                roles: ['USER'],
                password: hashedPassword,
                provider: user?.provider
            },
        });
        await this.cacheManager.set(savedUser.id, savedUser)
        await this.cacheManager.set(savedUser.email, savedUser)
        return savedUser
    }

    async findOne(idOrEmail: string, isReset = false) {
        console.log("findOne")
        if (isReset) {
            await this.cacheManager.del(idOrEmail)
        }
        const user = await this.cacheManager.get<User>(idOrEmail)
        if (!user) {
            const user = await this.prismaService.user.findFirst({
                where: {
                    OR: [{id: idOrEmail}, {email: idOrEmail}],
                },
            });
            if (!user) {
                return null
            }
            await this.cacheManager.set(idOrEmail, user, convertToSecondsUtil(this.configService.get("JWT_EXP")))
            return user
        }
        return user
    }

    async delete(id: string, user: JwtPayload) {
        console.log(user)
        if (user.id !== id && !user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException();
        }
        await Promise.all([
            this.cacheManager.del(id),
            this.cacheManager.del(user.email)
        ])


        // Проверяем наличие связанных записей в таблице 'tokens'
        const tokens = await this.prismaService.token.findMany({where: {userId: id}});

        if (tokens.length > 0) {
            // Обрабатываем связанные записи в 'tokens' (например, удаляем их)
            await this.prismaService.token.deleteMany({where: {userId: id}});
        }

        // Удаляем пользователя
        return this.prismaService.user.delete({where: {id}, select: {id: true}});
    }


    private hashPassword(password: string): string {
        return hashSync(password, genSaltSync(10));
    }
}
