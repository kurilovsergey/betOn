import { BadRequestException, Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { genSalt, hash } from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { UpdateUserDto } from './dto/update-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { JwtService } from '@nestjs/jwt';
import { checkIdForMongo } from 'src/tools/functions';
import { UpdateBalanceUserDto } from './dto/update-balance-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private usersModel: Model<User>,
    private readonly jwtService: JwtService,
  ) {}

  async getAllUsers(): Promise<User[]> {
    try {
      return await this.usersModel
        .find()
        .select(['name', 'username', 'email', 'balance', 'createdAt']);
    } catch (e) {
      throw new Error(e);
    }
  }

  async getByIdUser(id: string): Promise<User> {
    try {
      return await this.usersModel
        .findById(id)
        .select(['name', 'username', 'email', 'balance', 'createdAt']);
    } catch (e) {
      throw new Error(e);
    }
  }

  async createUser(userDto: CreateUserDto): Promise<User> {
    try {
      const salt = await genSalt(10);
      const hashPassword = await hash(userDto.password, salt);

      const newUser = new this.usersModel({
        ...userDto,
        password: hashPassword,
      }).save();

      //const token = this.jwtService.sign({ email: userDto.email });
      return newUser;
    } catch (e) {
      throw new Error(e);
    }
  }

  async removeUser(id: string): Promise<User> {
    try {
      return await this.usersModel.findByIdAndDelete(id);
    } catch (e) {
      throw new Error(e);
    }
  }

  async updateUser(id: string, userDto: UpdateUserDto): Promise<User> {
    try {
      return await this.usersModel.findByIdAndUpdate(id, userDto, {
        new: true,
      });
    } catch (e) {
      throw new Error(e);
    }
  }

  async updateUserBalance(
    id: string,
    updateBalanceUserDto: UpdateBalanceUserDto,
  ): Promise<User> {
    try {
      return await this.usersModel.findByIdAndUpdate(
        id,
        { balance: updateBalanceUserDto.balance },
        {
          new: true,
        },
      );
    } catch (e) {
      throw new Error(e);
    }
  }

  async getUserBalanceById(id_user: string): Promise<number> {
    try {
      checkIdForMongo(id_user);
      const user = await this.usersModel.findById(id_user);
      return user.balance;
    } catch (e) {
      throw new Error(e);
    }
  }

  async findOne(email: string): Promise<User | undefined> {
    try {
      return await this.usersModel.findOne({
        email,
      });
    } catch (e) {
      throw new Error(e);
    }
  }

  //проверка на сущестование и корректный ввод ид пользователя для бд mongo
  async checkUserById(id: string): Promise<boolean> {
    try {
      //проверка на ид для mongo
      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        throw new BadRequestException('Invalid entered id_user');
      }
      const user = await this.getByIdUser(id);
      if (!user) {
        throw new BadRequestException('Invalid entered id_user');
      }
      return true;
    } catch (e) {
      throw new Error(e);
    }
  }
}
