import { Injectable } from '@nestjs/common';
import { CreateCategoryDto } from './dto/create-category.dto';
import { Category } from './schemas/category.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { checkIdForMongo } from 'src/tools/functions';

@Injectable()
export class CategoriesService {
  constructor(
    @InjectModel(Category.name) private categoriesModel: Model<Category>,
  ) {}

  async getAllCategories(): Promise<Category[]> {
    try {
      return await this.categoriesModel.find();
    } catch (e) {
      throw new Error(e);
    }
  }

  async createCategory(
    createCategoryDto: CreateCategoryDto,
  ): Promise<Category> {
    try {
      const newCategory = await new this.categoriesModel(
        createCategoryDto,
      ).save();
      return newCategory;
    } catch (e) {
      throw new Error(e);
    }
  }

  async checkCategoryById(id_category: string): Promise<boolean> {
    try {
      checkIdForMongo(id_category);
      const caterory = await this.categoriesModel.findById(id_category);
      if (!caterory) {
        return false;
        //throw new BadRequestException('Category not found');
      }
      return true;
    } catch (e) {
      throw new Error(e);
    }
  }
}
