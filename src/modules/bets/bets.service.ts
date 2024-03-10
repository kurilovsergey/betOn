import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Bet } from './schemas/bet.schema';
import { CreateBetDto } from './dto/create-bet.dto';
import { UsersService } from 'src/modules/users/users.service';
import { checkIdForMongo } from 'src/tools/functions';
import { CategoriesService } from 'src/modules/categories/categories.service';

@Injectable()
export class BetsService {
  constructor(
    @InjectModel(Bet.name) private betsModel: Model<Bet>,
    private readonly usersService: UsersService,
    private readonly categoriesService: CategoriesService,
  ) {}

  async getAllBets(): Promise<Bet[]> {
    try {
      return await this.betsModel.find();
    } catch (e) {
      throw new Error(e);
    }
  }

  async getByIdBet(id: string): Promise<Bet> {
    try {
      return await this.betsModel.findById(id);
    } catch (e) {
      throw new Error(e);
    }
  }

  async createBet(betDto: CreateBetDto): Promise<Bet> {
    try {
      await this.usersService.checkUserById(betDto.id_user);
      const nowDate = new Date();
      const endDate = new Date(betDto.endDate);
      if (endDate.getTime() < nowDate.getTime()) {
        throw new BadRequestException('End date must be more than now');
      }
      /*
      TODO: добавить проверку на существование категорий
      let existedCategories = [];
      if (betDto.categories !== null) {
        betDto.categories.forEach(async (c) => {
          const tmpCategory = await this.categoriesService.checkCategoryById(c);
          console.log(tmpCategory);
          if (tmpCategory) {
            existedCategories.push(c);
          }
        });
      }
      if (existedCategories.length === 0) {
        existedCategories = null;
      }
      //добавление только существующих категорий
      const newBetDto = { ...betDto, categories: existedCategories };
      */
      const newBet = await new this.betsModel(betDto).save();
      return newBet;
    } catch (e) {
      throw new Error(e);
    }
  }

  //меняет статус пари
  async updateStatusByIdBet(id: string, status: boolean): Promise<Bet> {
    try {
      return await this.betsModel.findByIdAndUpdate(
        id,
        { status },
        {
          new: true,
        },
      );
    } catch (e) {
      throw new Error(e);
    }
  }

  async getBidsByIdUser(id_user: string): Promise<Bet[]> {
    try {
      await this.usersService.checkUserById(id_user);
      return await this.betsModel.find({ id_user });
    } catch (e) {
      throw new Error(e);
    }
  }

  async getBetsByIdCategory(id_category: string): Promise<Bet[]> {
    try {
      const existCategory =
        await this.categoriesService.checkCategoryById(id_category);
      if (!existCategory) {
        throw new BadRequestException('Category not found');
      }
      const bets = await this.betsModel.find({
        categories: { $in: [id_category] },
      });
      return bets;
    } catch (e) {
      throw new Error(e);
    }
  }

  //проверка на сущестование и корректный ввод ид пари для бд mongo
  async checkBetById(id: string): Promise<boolean> {
    try {
      checkIdForMongo(id);
      const bet = await this.getByIdBet(id);
      if (!bet) {
        throw new BadRequestException('Invalid entered id_bet');
      }
      return true;
    } catch (e) {
      throw new Error(e);
    }
  }

  //проверка на существование пари у этого пользователя
  async checkBetAndUserById(id_bet: string, id_user: string): Promise<boolean> {
    try {
      checkIdForMongo(id_bet);
      checkIdForMongo(id_user);
      const betForUser = await this.betsModel.find({
        _id: id_bet,
        id_user: id_user,
      });
      if (betForUser.length === 0) {
        throw new BadRequestException('Not found bet for this user');
      }
      return true;
    } catch (e) {
      throw new Error(e);
    }
  }
}
