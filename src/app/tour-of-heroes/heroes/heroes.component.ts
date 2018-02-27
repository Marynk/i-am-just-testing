import { Component, OnInit } from '@angular/core';
import { Hero } from '../heroModel';
import { AngularFireDatabase} from 'angularfire2/database';
import { Observable } from 'rxjs/Observable';
import { HeroService} from '../hero.service';

@Component({
  selector: 'app-heroes',
  templateUrl: './heroes.component.html',
  styleUrls: ['./heroes.component.scss']
})
export class HeroesComponent implements OnInit {

  heroes: Hero[];

  getHeroes(): void {
    this.heroService.getHeroes()
      .subscribe(heroes => this.heroes = heroes);
  }

  delete(hero: Hero): void{
    this.heroService.deleteHero(hero);
  }

  add(name: string){
    const id = this.heroes[this.heroes.length - 1].id + 1;
    this.heroService.addHero(name, id);
  }

  constructor(private heroService: HeroService) { }

  ngOnInit() {
    this.getHeroes();
  }

}
