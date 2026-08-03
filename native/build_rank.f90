module arach_build_rank_module
  use, intrinsic :: iso_c_binding, only: c_bool, c_double, c_int
  use, intrinsic :: ieee_arithmetic, only: ieee_is_finite
  implicit none
  private
  public :: arach_build_rank
  public :: arach_corpus_rank

contains

  function arach_build_rank(criticality, dependents, cache_hit, memory_gib, &
                            trust_admitted) result(score) bind(C)
    real(c_double), value :: criticality
    integer(c_int), value :: dependents
    logical(c_bool), value :: cache_hit
    real(c_double), value :: memory_gib
    logical(c_bool), value :: trust_admitted
    real(c_double) :: score
    real(c_double) :: cache_bonus
    real(c_double) :: memory_cost

    if (.not. trust_admitted) then
      score = -1.0_c_double
      return
    end if

    if (cache_hit) then
      cache_bonus = 8.0_c_double
    else
      cache_bonus = 0.0_c_double
    end if

    memory_cost = max(memory_gib, 0.0_c_double) * 0.25_c_double
    score = max(criticality, 0.0_c_double) * 10.0_c_double &
          + real(max(dependents, 0_c_int), c_double) * 2.0_c_double &
          + cache_bonus - memory_cost
  end function arach_build_rank

  function arach_corpus_rank(static_candidates, worker_candidates, quarantined, &
                             dependents, cache_hits, average_memory_gib, &
                             trust_admitted) result(score) bind(C)
    integer(c_int), value :: static_candidates
    integer(c_int), value :: worker_candidates
    integer(c_int), value :: quarantined
    integer(c_int), value :: dependents
    integer(c_int), value :: cache_hits
    real(c_double), value :: average_memory_gib
    logical(c_bool), value :: trust_admitted
    real(c_double) :: score
    real(c_double) :: candidate_value
    real(c_double) :: graph_value
    real(c_double) :: cache_value
    real(c_double) :: quarantine_cost
    real(c_double) :: memory_cost
    integer(c_int) :: candidate_count

    if (.not. trust_admitted .or. &
        static_candidates < 0_c_int .or. &
        worker_candidates < 0_c_int .or. &
        quarantined < 0_c_int .or. &
        dependents < 0_c_int .or. &
        cache_hits < 0_c_int .or. &
        .not. ieee_is_finite(average_memory_gib) .or. &
        average_memory_gib < 0.0_c_double) then
      score = -1.0_c_double
      return
    end if

    candidate_count = static_candidates + worker_candidates
    if (candidate_count == 0_c_int) then
      score = 0.0_c_double
      return
    end if

    ! Static candidates have the highest immediate conversion yield. Worker
    ! candidates remain valuable, but consume isolated execution capacity.
    candidate_value = real(static_candidates, c_double) * 4.0_c_double &
                    + real(worker_candidates, c_double) * 1.5_c_double
    graph_value = real(dependents, c_double) * 0.5_c_double
    cache_value = real(min(cache_hits, candidate_count), c_double)
    quarantine_cost = real(quarantined, c_double) * 3.0_c_double
    memory_cost = average_memory_gib * real(candidate_count, c_double) * 0.25_c_double

    score = candidate_value + graph_value + cache_value &
          - quarantine_cost - memory_cost
  end function arach_corpus_rank

end module arach_build_rank_module
