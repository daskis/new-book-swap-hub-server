import {JwtAuthGuard} from "./jwt-auth-guard";
import {RolesGuard} from "@auth/guards/role.guard";
import {GoogleGuard} from "@auth/guards/google.guard";
import {YandexGuard} from "@auth/guards/yandex.guard";

export const GUARDS = [JwtAuthGuard, RolesGuard, GoogleGuard, YandexGuard]
