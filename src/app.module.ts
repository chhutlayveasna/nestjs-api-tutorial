import { APP_PIPE } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { Module, ValidationPipe } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { BookmarkModule } from './bookmark/bookmark.module';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [AuthModule, UserModule, BookmarkModule, PrismaModule]
})
export class AppModule {}
