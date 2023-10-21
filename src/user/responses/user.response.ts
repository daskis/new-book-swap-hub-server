import {$Enums, Provider, Role, User} from "@prisma/client";
import {Exclude} from "class-transformer";

export class UserResponse implements User {
    email: string;
    id: string;

    @Exclude()
    password: string;
    roles: Role[];

    @Exclude()
    provider: Provider

    @Exclude()
    createdAt: Date;

    @Exclude()
    updatedAt: Date;

    constructor(user: User) {
        Object.assign(this, user)
    }


}