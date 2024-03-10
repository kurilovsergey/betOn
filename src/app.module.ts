import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { BetsModule } from './modules/bets/bets.module';
import { BidsModule } from './modules/bids/bids.module';
import { CategoriesModule } from './modules/categories/categories.module';
import { EvidencesModule } from './modules/evidences/evidences.module';

@Module({
  imports: [
    UsersModule,
    AuthModule,
    BetsModule,
    BidsModule,
    CategoriesModule,
    EvidencesModule,
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (config: ConfigService) => ({
        uri: config.get<string>('MONGODB_URI'),
      }),
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
