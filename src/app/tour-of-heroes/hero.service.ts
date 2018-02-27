import { Injectable } from '@angular/core';
import { Hero } from './heroModel';
import { Observable } from 'rxjs/Observable';
import { AngularFireDatabase } from 'angularfire2/database';
import { database } from 'firebase';

import { of} from 'rxjs/observable/of';

@Injectable()
export class HeroService {

  heroDB: Observable<any[]>;

  hero: Hero;

   getHeroes():  Observable<any[]>{
    return this.heroDB;

  }
  updateHero(hero: Hero): Observable<any>{
     return of(database().ref('/heroes/' + hero.id).update(hero));
  }

  deleteHero(hero: Hero): void{
    database().ref('/heroes/' + hero.id).remove();
  }

  addHero(heroname: string, id: number): void{

     database().ref('/heroes/' + id).set({'id': id, 'name': heroname});
  }
  constructor(db: AngularFireDatabase) {
    this.heroDB = db.list('/heroes').valueChanges();
  }

}
