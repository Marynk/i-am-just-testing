import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { HeroService} from ".//hero.service";

import { HeroRoutingModule } from ".//hero-routing.module"
import {HeroesComponent} from "./heroes/heroes.component";
import {TourOfHeroesComponent} from "./tour-of-heroes.component";
import { DashboardComponent} from "./dashboard/dashboard.component"
import {HeroDetailComponent} from "./hero-detail/hero-detail.component";

@NgModule({
  declarations: [
    TourOfHeroesComponent,
    DashboardComponent,
    HeroDetailComponent,
    HeroesComponent
  ],
  imports: [
    BrowserModule,
    HeroRoutingModule,
    FormsModule
  ],
  providers: [HeroService],
})
export class HeroModule { }
