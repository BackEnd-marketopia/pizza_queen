@extends('layouts.admin.app')

@section('title', translate('Add New Menu'))

@section('content')
    <div class="content container-fluid">
        <h2 class="h1 mb-4">{{ translate('Add New Menu') }}</h2>

        <div class="card">
            <div class="card-body">
                <form action="{{ route('admin.menu.menu.store') }}" method="POST" enctype="multipart/form-data">
                    @csrf

                    <div class="mb-3">
                        <label class="form-label">{{ translate('Menu Image') }}</label>
                        <br>
                        <input type="file" name="image" class="form-control" required>
                    </div>
                    <br>
                    <div class="text-end">
                        <button type="submit" class="btn btn-primary">{{ translate('Submit') }}</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
@endsection