import { Component, OnInit } from '@angular/core';
import { Hero } from '../heroModel';
import { HeroService } from '../hero.service';
import {Observable} from 'rxjs/Observable';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: [ './dashboard.component.css' ]
})
export class DashboardComponent implements OnInit {

  dasharr: Hero[] = [];
  constructor(private heroService: HeroService) { }

  ngOnInit() {
    this.getHeroes();
  }

  getHeroes(): void {
    this.heroService.getHeroes()
      .subscribe(heroes => this.dasharr = heroes.slice(1, 5));
  }
}
