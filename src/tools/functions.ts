import { BadRequestException } from '@nestjs/common';

//проверка на ид для mongo
export function checkIdForMongo(id: string): boolean {
  if (!id.match(/^[0-9a-fA-F]{24}$/)) {
    throw new BadRequestException('Invalid data');
  }
  return true;
}
